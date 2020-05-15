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
     */
    public function login(AuthenticationUtils $authenticationUtils, UserRepository $userRepository, Request $request): Response
    {
        // if ($this->getUser()) {
        //     return $this->redirectToRoute('target_path');
        // }
        // get the login error if there is one
        $error = $authenticationUtils->getLastAuthenticationError();
        // last username entered by the user
        $lastUsername = $authenticationUtils->getLastUsername();

        $checkBrowserMessage = false;

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error, 'checkBrowserMessage' => $checkBrowserMessage]);
    }

    /**
     * @Route("/logout", name="app_logout")
     */
    public function logout()
    {
    }


    /**
     * @Route("/2fa", name="2fa_login")
     */
    public function check2fa(EntityManagerInterface $entityManagerInterface, Request $request, TokenStorageInterface $tokenStorageInterface, GoogleAuthenticatorInterface $googleAuthenticatorInterface)
    {
        $user = $this->getUser();
        if(!$user->getBrowserStatus()){
            $this->get('security.token_storage')->setToken(null);
            $entityManagerInterface->persist($user);
            $entityManagerInterface->flush();
            return $this->redirectToRoute('app_check_browser',['id' => $user->getId()]);
        }
        
        $qrCode = $googleAuthenticatorInterface->getQRContent($user);
        $url = "http://chart.apis.google.com/chart?cht=qr&chs=150x150&chl=".$qrCode;
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
        $checkBrowser = new CheckBrowser();
        $form = $this->createForm(CheckBrowserType::class, $checkBrowser);
        
        $form->handleRequest($request);

        if($form->isSubmitted() && $form->isValid()){
            if($user->getBrowserToken() == $checkBrowser->getBrowserToken()){
                $user->setUsualBrowser($user->getCheckBrowserName());
                $user->setBrowserStatus(true);
                $user->setCheckBrowserName(null);
                $entityManagerInterface->persist($user);
                $entityManagerInterface->flush();
            }
    
            if(!$user->getBrowserStatus()){
                $this->addFlash(
                    'danger',
                    'Le code de validation n\'est pas valide'
                );
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
