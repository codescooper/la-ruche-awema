"""Manually reviewed, expurgated narrative; emitted only for exact matching evidence.
No model-generated text, private prompts or message contents leave this reader.
"""
import hashlib,json
EXPECTED = [{'id': 8403, 'session_id': '20260925_013054_8fb1e2', 'sha256': 'cbfdc5ea0e52dcb742ba24055491528c08402ae1fbe7f15e26978ba18a5f76d3'}, {'id': 8430, 'session_id': '20260925_013231_f5394d', 'sha256': '472ee747e5177e329ae2338c870b2f9ac34eae8d489fadcdff735b7aafbfb403'}, {'id': 8443, 'session_id': '20260925_013054_8fb1e2', 'sha256': 'fc97ca57d8b8a5af2e9ecb59fbf20a4ef3a8b946927e64b5546053b3430f7fc0'}, {'id': 8476, 'session_id': '20260925_013621_4f86af', 'sha256': '26bdab5f5ab0fcd7c0b9ad65e0a3cb1e3c51317c02651bfea25e1a6f4f8471f1'}, {'id': 8487, 'session_id': '20260925_013054_8fb1e2', 'sha256': 'b1179f08a6ecfef92c8a379a41e4bd55e86d5c38197f3e04a915472310589177'}]

def get_story(db, task_id, root_sid, actor_id_by_session):
    if task_id!='t_97066a56' or root_sid!='20260925_013054_8fb1e2':return None
    for expected in EXPECTED:
        row=db.execute('SELECT session_id,content,tool_calls FROM messages WHERE id=?',(expected['id'],)).fetchone()
        if not row or row[0]!=expected['session_id']:return None
        digest=hashlib.sha256(json.dumps([row[1],row[2]],ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
        if digest!=expected['sha256']:return None
    root=actor_id_by_session.get(root_sid)
    mentor=actor_id_by_session.get('20260925_013231_f5394d')
    qa=actor_id_by_session.get('20260925_013621_4f86af')
    if not all([root,mentor,qa]):return None
    return {
      'title':"Préparer les prochaines décisions de l’équipe",
      'objective':"Préparer les prochaines décisions de l’équipe à partir des dossiers disponibles, en conservant les validations humaines requises.",
      'result':"Le rapport d’exécution déclare une synthèse actualisée, une note Mentor et une revue QA documentaire reçues. Aucun chantier métier débloqué, aucun test de production effectué.",
      'limitations':"Résumé expurgé relu à partir des demandes de délégation et des réponses finales. QA signale une source partiellement lisible : son avis ne vaut pas validation du système ni des produits.",
      'steps':[
        {'at':1790299862,'scene':{'kind': 'read', 'speaker': 'cto', 'recipient': None, 'tool': 'read'},'actor':root,'text':"Le CTO consulte la carte puis les documents de contexte. Les lectures d’outils sont enregistrées ; leur contenu privé n’est pas publié."},
        {'at':1790299951,'scene':{'kind': 'delegate', 'speaker': 'cto', 'recipient': 'mentor', 'tool': 'delegate'},'actor':root,'text':"Le CTO délègue au Mentor une note de préparation : obstacles, décisions attendues et prochaine preuve, sans contacter de tiers."},
        {'at':1790300016,'scene':{'kind': 'return', 'speaker': 'mentor', 'recipient': 'cto', 'tool': 'write'},'actor':mentor,'text':"Le sous-agent chargé du Mentor remet sa note et déclare avoir vérifié son écriture. Il indique qu’un retour humain reste nécessaire et ne revendique aucune avancée métier."},
        {'at':1790300181,'scene':{'kind': 'delegate', 'speaker': 'cto', 'recipient': 'qa', 'tool': 'review'},'actor':root,'text':"Le CTO demande une revue QA indépendante de la synthèse : cohérence des références, priorités, limites et maintien des validations."},
        {'at':1790300302,'scene':{'kind': 'return', 'speaker': 'qa', 'recipient': 'cto', 'tool': 'review'},'actor':qa,'text':"Le sous-agent chargé de QA retourne un avis documentaire favorable avec réserve : la source n’est que partiellement lisible. Il demande un export lisible avant une décision opérationnelle."},
        {'at':1790300343,'scene':{'kind': 'close', 'speaker': 'cto', 'recipient': None, 'tool': 'none'},'actor':root,'text':"La carte est clôturée comme préparation documentaire. Cette clôture ne signifie ni mise en production ni résolution des chantiers bloqués."}
      ]}
