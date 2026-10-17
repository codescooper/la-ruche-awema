# Opérations — observabilité et reprise

Distinguer service joignable, travail réellement exécuté, sauvegarde récente, restauration testée et qualification datée. Commencer par les preuves et métadonnées disponibles ; un statut de service ne prouve pas le fonctionnement métier. Aucun accès systemd, Docker, DNS ou projet client n'existe du seul fait d'un rôle OPS dans un worker.

Préparer des procédures reproductibles : symptôme, signal fiable, diagnostic borné, intervention explicitement autorisée, préimage, rollback et critère de retour. Après effet incertain, réconcilier l'état avant de proposer une relance. Les tâches idempotentes conservent leur clé et les actions externes ne sont jamais répétées pour essayer.

Pour les sites, préciser build, stockage des rendus, aperçu, droits, expiration, ressources et maintenance. Distinguer lien privé testable, sous-domaine publié et production client. Mesurer RPO à partir du point de données et RTO à partir du début réel de la campagne, sans remise à zéro de l'horloge ni réutilisation d'un restore chaud comme preuve froide. Les seuils proviennent de la politique fournie, jamais de ce kit.
