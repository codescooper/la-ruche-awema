"""Finite demo capabilities. Never evaluates code, paths, SQL, URLs or commands."""
import json
from decimal import Decimal, InvalidOperation
from catalog import ROLE_IDS

def validate_plan(plan):
    if not isinstance(plan, dict) or set(plan) - {'action', 'reply', 'quantity', 'unit_price', 'draft', 'needs', 'plan'}:
        raise ValueError('invalid_plan')
    if plan.get('action') not in ('chat', 'quote', 'qa', 'story', 'clarify', 'refuse'):
        raise ValueError('unsupported_action')
    for key, limit in [('reply', 5000), ('draft', 6000)]:
        if key in plan and (not isinstance(plan[key], str) or len(plan[key]) > limit):
            raise ValueError('invalid_text')
    for key in ('needs', 'plan'):
        if key in plan and (not isinstance(plan[key], list) or len(plan[key]) > 8 or any(not isinstance(x, str) or len(x)>350 for x in plan[key])):
            raise ValueError('invalid_list')
    return plan

def execute_plan(plan):
    plan = validate_plan(plan)
    action = plan['action']
    steps = [{'role':'cto','title':'Objectif analysé','detail':'Interprétation par le modèle, dans le périmètre de démonstration.', 'status':'completed'}]
    for item in plan.get('plan', [])[:4]:
        steps.append({'role':'cto','title':'Plan proposé','detail':item,'status':'completed'})
    result = {'status':'completed','reply':plan.get('reply',''),'steps':steps,'artifact':None}
    if action in ('refuse','clarify'):
        result['status'] = 'needs_input' if action=='clarify' else 'refused'
        steps.append({'role':'security' if action=='refuse' else 'pm','title':'Arrêt contrôlé','detail':plan.get('reply','Informations ou autorisation manquantes.'),'status':'completed'})
    elif action in ('quote','qa'):
        try:
            q=Decimal(str(plan.get('quantity', ''))); p=Decimal(str(plan.get('unit_price', '')))
            if not q.is_finite() or not p.is_finite() or q<=0 or q>10000 or p<0 or p>10000000 or q!=q.to_integral_value() or p.as_tuple().exponent < -2:
                raise ValueError()
        except (InvalidOperation,ValueError):
            return {'status':'needs_input','reply':'Indiquez une quantité entière de 1 à 10 000 et un prix unitaire de 0 à 10 000 000 FCFA, avec au plus deux décimales. Aucun chiffre manquant n’a été inventé.','steps':steps,'artifact':None}
        total=q*p
        # Two distinct checks: multiplication and repeated addition, bounded to 10k.
        verified=sum((p for _ in range(int(q))),Decimal(0))
        assert total==verified
        steps.append({'role':'dev','title':'Calcul exécuté','detail':f'{q} × {p} = {total} FCFA. Outil arithmétique borné, sans code utilisateur.','status':'completed'})
        if action=='qa':
            bad=total+1
            steps.append({'role':'qa','title':'Anomalie volontaire détectée','detail':f'La fixture proposait {bad} FCFA. Le vérificateur a rejeté ce total : attendu {verified}.','status':'completed'})
            steps.append({'role':'dev','title':'Correction appliquée à la fixture','detail':f'Total de démonstration corrigé à {total} FCFA.','status':'completed'})
        steps.append({'role':'qa','title':'Vérification indépendante du calcul','detail':f'Addition répétée exécutée : {verified} FCFA. Les deux résultats concordent.','status':'completed'})
        result['artifact']={'title':'Devis fictif — brouillon non engageant','content':f'Quantité : {q}\nPrix unitaire : {p} FCFA\nTotal vérifié : {total} FCFA\nAucune taxe, réservation, dépense ou commande ajoutée.','kind':'quote'}
        result['reply']=f'Le brouillon est prêt : {q} × {p} = {total} FCFA. '+('L’erreur volontaire a été détectée et corrigée. ' if action=='qa' else '')+'Consultez les étapes de calcul et de vérification ci-dessous.'
    elif action=='story':
        draft=plan.get('draft','').strip()
        if not draft:
            result.update(status='needs_input',reply='Fournissez un court scénario fictif ; je ne peux pas inventer un scénario à votre place.')
        else:
            result['artifact']={'title':'Dépouillement fictif — à relire','content':draft,'kind':'story'}
            steps.append({'role':'cl-producer','title':'Brouillon produit par le modèle','detail':'Analyse textuelle de votre scénario fictif. Aucune recherche de personnes, de lieux ou de matériel.','status':'completed'})
            steps.append({'role':'qa','title':'Contrôle de structure','detail':'Présence et taille du brouillon contrôlées par le serveur. Fidélité artistique à relire humainement.','status':'completed'})
    if plan.get('needs'):
        result['reply'] += '\n\nÀ préciser : ' + '; '.join(plan['needs'])
    return result
