<?php

namespace App\Controller;

use App\Entity\User;
use Symfony\Component\Form\Form;
use App\Form\RegistrationFormType;
use Symfony\Component\Form\FormError;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\ConstraintViolationList;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Validator\Constraints\NotCompromisedPassword;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticatorInterface;

class RegistrationController extends AbstractController
{
    /**
     * @Route("/register", name="app_register")
     * Register function; checking and saving all the needed values
     */
    public function register(ValidatorInterface $validator, EntityManagerInterface $entityManager, GoogleAuthenticatorInterface $googleAuthenticatorInterface, Request $request, UserPasswordEncoderInterface $passwordEncoder): Response
    {
        // We create a new user
        $user = new User();

        // We create a new form from the RegistrationFormType 
        $form = $this->createForm(RegistrationFormType::class, $user);
        
        // We fill the form with the request content
        $form->handleRequest($request);
        
        // If the form is OK
        if ($form->isSubmitted() && $form->isValid()) {
            // Create a new validator of the password (not compromised in a data breach)
            $violations = $validator->validate($form->get('plainPassword')->getNormData(), [
                new NotCompromisedPassword(),
            ]);

            // If compromised assign the error to the password field
            if ($user->getCheckPassword() && $violations instanceof ConstraintViolationList && $violations->count()) {
                $password = $form->get('plainPassword');
                if ($password instanceof Form) {
                    $violationMessage = "Ce mot de passe a été divulgué lors d'une violation de données, il ne doit pas être utilisé. Veuillez utiliser un autre mot de passe.";
                    $password->addError(new FormError((string) $violationMessage));
                }
            } else {
                // encode the plain password
                $user->setPassword(
                    $passwordEncoder->encodePassword(
                        $user,
                        $form->get('plainPassword')->getData()
                    )
                );

                        
                // Gathering user IP 
                $userIp = system("curl -s ipv4.icanhazip.com");
                $user->setUsualIp($userIp);

                // Gathering IP informations for country checking
                $db = new \IP2Location\Database ('../src/Database/IP2LOCATION.BIN', \IP2Location\Database::FILE_IO);
                $ipInfos = $db->lookup($userIp, \IP2Location\Database::ALL);
                
                // we save the user country at registration time as the default one
                $user->setCountryName($ipInfos['countryName']);
                
                // We create a new secret key for the account (double authentication token)
                $user->setGoogleAuthenticatorSecret($googleAuthenticatorInterface->generateSecret());

                // We get the Server informations containing the browser informations
                $u_agent = $_SERVER['HTTP_USER_AGENT'];

                // we set a default browser name
                $bname = 'Unknown';
        
                // Next get the name of the useragent separately 
                // and saves a custom string corresponding to the browser
                if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent)){
                  $bname = 'Internet Explorer';
                }elseif(preg_match('/Firefox/i',$u_agent)){
                  $bname = 'Mozilla Firefox';
                }elseif(preg_match('/OPR/i',$u_agent)){
                  $bname = 'Opera';
                }elseif(preg_match('/Chrome/i',$u_agent) && !preg_match('/Edge/i',$u_agent)){
                  $bname = 'Google Chrome';
                }elseif(preg_match('/Safari/i',$u_agent) && !preg_match('/Edge/i',$u_agent)){
                  $bname = 'Apple Safari';
                }elseif(preg_match('/Netscape/i',$u_agent)){
                  $bname = 'Netscape';
                }elseif(preg_match('/Edge/i',$u_agent)){
                  $bname = 'Edge';
                }elseif(preg_match('/Trident/i',$u_agent)){
                  $bname = 'Internet Explorer';
                }

                // Get the user mail
                $userEmail = $user->getEmail();

                // We save a token that'll be used for confirmation mails
                $browserToken = strtoupper($userEmail[0]) . $userEmail[strlen($userEmail) - 1] . mt_rand(1000, 9999);

                // save the informations on the user entity
                $user->setUsualBrowser($bname);
                $user->setBrowserToken($browserToken);
                $user->setBrowserStatus(true);

                // We save the user in the database
                $entityManager->persist($user);
                
                // We clear the entity manager
                $entityManager->flush();               

                return $this->redirectToRoute('app_login');
            }
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form->createView(),
        ]);
    }
}
