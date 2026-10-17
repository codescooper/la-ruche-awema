# Preuves et remise

Une affirmation « testé » nomme la commande ou l'outil réellement exécuté, les fichiers exacts, le résultat et la limite de cette vérification. Une compilation n'est pas un test d'usage ; une capture n'est pas une revue visuelle par un modèle sans outil de vision ; une sortie de modèle n'est pas une preuve indépendante.

Dans un worker natif, conserver une progression honnête dans RESULT.json selon STAGE, et finaliser les artefacts réellement présents. Ne pas déclarer les fichiers du kit comme livrables. Dans une conversation sans outils, donner une réponse utile et sourcée sans prétendre créer un fichier ou exécuter une commande. Les journaux de chargement sont établis par l'opérateur : rôle, version, empreintes, task/run/image et montage lecture seule. Ils prouvent les octets fournis au prompt, pas leur compréhension ni la qualité métier.

Avant remise : vérifier complétude métier, cohérence des données et du texte, absence de secrets, noms/formats, reproductibilité des contrôles et accessibilité du rendu demandé. Un manque reste explicitement déclaré. Le livrable final doit être simple à comprendre : résultat, comment l'utiliser/tester, limites et prochaine décision.

Amélioration continue : décrire une erreur réellement observée, sa cause étayée, la correction et la non-régression correspondante. Une proposition de mise à jour d'un kit comporte version, sources effectivement consultées et cas d'évaluation ; seule une mise à jour revue et épinglée pourra être chargée. Aucun auto-apprentissage fictif ni modification autonome du kit monté en lecture seule.
