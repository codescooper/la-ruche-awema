# La Ruche AWEMA

Un bureau d'agents IA pour transformer un objectif en travail coordonné, observable et vérifiable.

**Site du projet : https://laruche.awema.cloud/**

Le CTO coordonne la mission ; le chef de projet prépare le plan ; les spécialistes produisent, les rôles de contrôle vérifient, puis l'opérateur explore et valide les livrables. Le bureau isométrique montre l'activité ; **la Danse** permet le suivi et la relecture des événements enregistrés. Les événements enregistrés ne constituent pas une transcription de la pensée interne des modèles.

## Contenu du dépôt

| Dossier | Contenu |
|---|---|
| `apps/bureau` | Bureau isométrique, navigation, personnages et interface publique |
| `apps/finance` | Espace privé, chat, missions, plans, finance, livrables et prévisualisation |
| `apps/danse` | Projection en lecture seule, suivi et replay des missions |
| `apps/observer` | Observateurs, journaux et portail historique |
| `apps/previews` | Présentation des sites livrés sur un environnement séparé |
| `core` | Commandes de tâches, approbations, audit, gestion des secrets et broker |
| `integrations` | Telegram, GitHub, passerelle de modèles et télémétrie de sécurité |
| `agent-kits` | Méthodes, critères et outils par métier |
| `toolkits/web` | Construction et contrôle des livrables web |
| `ops` | Sources de sauvegarde et de vérification de restauration |
| `tests` | Suites métier et navigateur issues du développement |
| `experimental/elevenlabs` | Candidat vocal : opt-in, cache, quota et contrôles d'accès |

## État de cette publication

Instantané des sources collectées le **17 octobre 2026**, avec les surcharges de code actives identifiées lors de l'export. Les modules expérimentaux sont distingués du fonctionnement déployé. Ce dépôt est une consolidation du projet : ce n'est pas l'historique intégral des interventions ni une copie des données de production.

**Le raccordement ElevenLabs n'est pas déclaré opérationnel.** Le dernier essai de démarrage de sa passerelle a été interrompu, puis arrêté, avant de modifier le viewer en service. Le candidat nécessite encore une validation d'intégration et de lecture audio réelle.

La publication du code ne vaut pas qualification « READY » ni garantie d'autonomie complète. Les autorisations humaines restent nécessaires pour les actions sensibles et les projets en production.

## Commencer

1. Lire [l'architecture](docs/ARCHITECTURE.md) et [les instructions d'installation](docs/INSTALLATION.md).
2. Préparer un environnement isolé et une configuration propre à votre installation.
3. Injecter les accès par un gestionnaire de secrets ; ne jamais les ajouter au dépôt.
4. Exécuter les contrôles hors ligne avant les tests d'intégration et navigateur.

```powershell
python tools/check_sources.py
```

Les sources actuelles utilisent des sockets Unix, des utilisateurs système dédiés, des chemins `/opt/awema-*`, des projections SQLite et des vérifications de versions. Leur déploiement complet demande une adaptation d'infrastructure ; aucun script de cette publication ne doit être lancé directement sur un serveur de production sans revue.

## Données et droits

Les clés, fichiers d'environnement réels, comptes, sessions, conversations, données financières, missions réelles, bases, sauvegardes et projets clients sont exclus. La configuration fournie est un exemple généré, sans identité réelle. Les références à des adresses publiques de serveurs ont été remplacées par une adresse de documentation.

Les licences et avis tiers sont conservés : voir [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). La publication publique n'attribue pas automatiquement une licence libre à l'ensemble du code original AWEMA ni à la marque.
