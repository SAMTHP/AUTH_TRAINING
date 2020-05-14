<?php

namespace App\Controller;

use App\Repository\UserRepository;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Serializer\SerializerInterface;
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
    public function check2fa(Request $request, TokenStorageInterface $tokenStorageInterface, GoogleAuthenticatorInterface $googleAuthenticatorInterface)
    {
        if(count($this->container->get('session')->getFlashBag()->get('browserCheck')) > 0){
            $this->get('security.token_storage')->setToken(null);
            
            return $this->redirectToRoute('app_login',['checkBrowser' => 'true']);
        }
        
        $qrCode = $googleAuthenticatorInterface->getQRContent($this->getUser());
        $url = "http://chart.apis.google.com/chart?cht=qr&chs=150x150&chl=".$qrCode;
        return $this->render(
            'security/2fa_login.html.twig', [
                'url' => $url
            ]
        );
    }
}
