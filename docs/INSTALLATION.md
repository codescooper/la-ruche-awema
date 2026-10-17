# Installation et vérification

## Prérequis

Python 3.11 ou ultérieur pour les composants de service ; Node.js pour les outils web et les tests JavaScript ; Linux avec sockets Unix, systemd et Docker pour l'architecture d'exploitation historique. Certains tests navigateur nécessitent Playwright. Le runtime natif de l'équipe dépend également de Hermes Agent, qui doit être installé séparément conformément à sa licence.

## Environnement de développement

Commencer par `python tools/check_sources.py`. Ce contrôle compile la syntaxe Python et vérifie les exclusions ; il ne démarre aucun service ni ne contacte un fournisseur. Pour consulter l'interface statique dans un bac local :

```
python -m http.server 8080 --directory apps/bureau --bind 127.0.0.1
```

Cette prévisualisation seule ne fournit pas les API de mission ou l'authentification.

## Déploiement complet

1. Configurer les identités, groupes, volumes et sockets Unix dédiés dans un environnement vierge.
2. Adapter les chemins, endpoints et politiques à votre installation ; les adresses `203.0.113.10` sont des exemples non routables.
3. Créer séparément les bases et comptes internes ; aucune donnée de démarrage réelle n'est distribuée.
4. Installer le runtime Hermes et les dépendances de chaque intégration depuis leurs sources officielles.
5. Approvisionner les secrets hors Git. Les variables et fichiers de clés ne font pas partie du dépôt.
6. Configurer le reverse proxy, le TLS, les projections et leur cadence ; vérifier l'isolation et les refus d'accès.
7. Exécuter une mission témoin, ses contrôles indépendants, son replay et l'ouverture du livrable avant toute qualification.

Plusieurs points d'entrée comportent des empreintes ou chemins de version vérifiés : les recalculer sur les sources effectivement revues plutôt que supprimer les contrôles. Les suites historiques sous `tests` peuvent nécessiter les fixtures et chemins de leur version d'origine. Aucune suite d'intégration ne doit être exécutée sur les données de production par défaut.

## Voix expérimentales

Le candidat ElevenLabs nécessite une licence fournisseur adaptée, une clé limitée, une passerelle dédiée, une configuration de voix/quota, le consentement dans l'interface et une session autorisée. Les événements historiques sont narrés par le journal système ; ils ne prouvent pas un dialogue détaillé entre workers. Son intégration reste à terminer.
