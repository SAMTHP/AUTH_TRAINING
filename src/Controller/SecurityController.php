<?php

namespace App\Controller;

use App\Entity\CheckBrowser;
use App\Entity\User;
use App\Form\CheckBrowserType;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google\GoogleAuthenticatorInterface;

class SecurityController extends AbstractController
{
    /**
     * @Route("/login", name="app_login")
     * Function rendering the login page
     */
    public function login(AuthenticationUtils $authenticationUtils, UserRepository $userRepository, Request $request): Response
    {
        // Get last authentication error message for view display
        $error = $authenticationUtils->getLastAuthenticationError();

        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        // $checkBrowserMessage = false;
        // , 'checkBrowserMessage' => $checkBrowserMessage

        // Renders the vue with the last username and error values passed to it
        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    /**
     * @Route("/logout", name="app_logout")
     * function for logout : We call it and it's catched by symfony to disconnect the current user.
     */
    public function logout()
    {
    }


    /**
     * @Route("/2fa", name="2fa_login")
     * 2 factor authentification
     */
    public function check2fa(EntityManagerInterface $entityManagerInterface, Request $request, TokenStorageInterface $tokenStorageInterface, GoogleAuthenticatorInterface $googleAuthenticatorInterface)
    {
        $user = $this->getUser();

        // do it only if the browser status is ok (no need to confirm by mail)
        if(!$user->getBrowserStatus()){
            // Code made to avoid a problem where the user need to validate via mail but accesses the double auth anyway
            $this->get('security.token_storage')->setToken(null);
            $entityManagerInterface->persist($user);
            $entityManagerInterface->flush();
            return $this->redirectToRoute('app_check_browser',['id' => $user->getId()]);
        }

        // Generates a qr code from the user saved token
        $qrCode = $googleAuthenticatorInterface->getQRContent($user);
        $url = "http://chart.apis.google.com/chart?cht=qr&chs=150x150&chl=".$qrCode;
        
        // Renders the view with the QRcode.
        return $this->render(
            'security/2fa_login.html.twig', [
                'url' => $url
            ]
        );
    }

    /**
     * Allow to check if browser token is valid
     * 
     * @Route("/check_browser/{id}", name="app_check_browser")
     *
     * @return Response
     */
    public function checkBrowserToken(EntityManagerInterface $entityManagerInterface, User $user, Request $request)
    {
        // Instantiate new checkBrowser
        $checkBrowser = new CheckBrowser();
        
        // Create a new form of checkBrowserType
        $form = $this->createForm(CheckBrowserType::class, $checkBrowser);
        
        // Fill the form with the request content
        $form->handleRequest($request);

        // If the form is submitted and vlaid
        if($form->isSubmitted() && $form->isValid()){
            // If the browser token is the same as the one saved
            if($user->getBrowserToken() == $checkBrowser->getBrowserToken()){
                // We set the new browser as the regular one
                $user->setUsualBrowser($user->getCheckBrowserName());
                $user->setBrowserStatus(true);
                $user->setCheckBrowserName(null);

                // We save the user modifications in the DB
                $entityManagerInterface->persist($user);

                // We clear the entity managber
                $entityManagerInterface->flush();
            }
            
            // If the user getBrowserStatus == null
            if(!$user->getBrowserStatus()){
                $this->addFlash(
                    'danger',
                    'Le code de validation n\'est pas valide'
                );
                // redirect to the check browser view
                return $this->redirectToRoute('app_check_browser',['id' => $user->getId()]);
            } else {
                $this->addFlash(
                    'success',
                    'Le code de validation est valide, vous pouvez vous connecter'
                );
                return $this->redirectToRoute('app_login');
            }
        }

        return $this->render('security/checkBrowser.html.twig', [
            'form' => $form->createView()
        ]);
    }
}
