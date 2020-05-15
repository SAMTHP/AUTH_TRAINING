<?php

namespace App\Repository;

use App\Entity\CheckBrowser;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @method CheckBrowser|null find($id, $lockMode = null, $lockVersion = null)
 * @method CheckBrowser|null findOneBy(array $criteria, array $orderBy = null)
 * @method CheckBrowser[]    findAll()
 * @method CheckBrowser[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class CheckBrowserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, CheckBrowser::class);
    }

    // /**
    //  * @return CheckBrowser[] Returns an array of CheckBrowser objects
    //  */
    /*
    public function findByExampleField($value)
    {
        return $this->createQueryBuilder('c')
            ->andWhere('c.exampleField = :val')
            ->setParameter('val', $value)
            ->orderBy('c.id', 'ASC')
            ->setMaxResults(10)
            ->getQuery()
            ->getResult()
        ;
    }
    */

    /*
    public function findOneBySomeField($value): ?CheckBrowser
    {
        return $this->createQueryBuilder('c')
            ->andWhere('c.exampleField = :val')
            ->setParameter('val', $value)
            ->getQuery()
            ->getOneOrNullResult()
        ;
    }
    */
}
