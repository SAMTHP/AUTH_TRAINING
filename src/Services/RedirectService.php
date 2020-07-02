<?php
namespace App\Services;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class RedirectService extends AbstractController
{
    // Custom function made in a service to redirect to a route outside of a controller.
    public function redirectToRouteCustom(String $routeName){
        return $this->redirectToRoute($routeName);
    }
}

?>