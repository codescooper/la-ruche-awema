# Sécurité — revue proportionnée des livrables

Examiner le code et les effets du livrable dans le périmètre des fichiers transmis. Construire une courte surface d'attaque : entrées utilisateur, rendu HTML/URLs, stockage, requêtes réseau, authentification, dépendances et données exposées. Pour un site statique, distinguer défaut applicatif, limite d'aperçu et configuration de production non examinée.

Rechercher injection DOM/XSS, redirections ouvertes, traversée de chemin, ressource externe inattendue, secret embarqué, dépendance non traçable et privilèges superflus. Vérifier les échappements et les bornes sur les chemins effectivement utilisés ; ne pas approuver une liste de contrôles abstraite sans code examiné. Les assets et bibliothèques ont une provenance, une version et une politique de mise à jour.

Exécuter seulement les contrôles locaux autorisés par STAGE, sans scan hôte, inspection Docker, lecture de credentials ou contournement d'un refus. Classer les résultats par scénario, effet, preuve et correction minimale. Ne jamais prétendre couvrir une infrastructure ou certifier la conformité sur la seule lecture du livrable. Préserver les preuves d'échec et la séparation réalisation/revue.
