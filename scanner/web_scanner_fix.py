"""
Correctif pour le scanner SSTI — version améliorée
"""

def _test_ssti_v2(self):
    """Test SSTI amélioré avec vérification stricte"""
    print(f"  [*] Test SSTI...")
    
    test_params = ["name", "user", "template", "view", "file", "page"]
    
    # On utilise des payloads qui produisent des résultats UNIQUES et spécifiques
    payloads = [
        ("{{7*'7'}}", "7777777"),  # Produit une chaîne de 7 '7'
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("{{7*7}}", "49"),
        ("#{7*7}", "49"),
        ("*{7*7}", "49"),
    ]
    
    import requests
    
    try:
        for param in test_params:
            for payload, expected in payloads:
                try:
                    r = self.session.get(
                        f"{self.url}?{param}={urllib.parse.quote(payload)}",
                        timeout=10
                    )
                    
                    # Vérification STRICTE : le payload ne doit PAS apparaître dans la réponse
                    # ET le résultat attendu DOIT apparaître
                    if payload not in r.text and expected in r.text:
                        # Vérification supplémentaire : la page doit avoir un status 200
                        # et avoir du contenu HTML normal
                        if r.status_code == 200 and len(r.text) > 100:
                            self.results["ssti"].append({
                                "url": f"{self.url}?{param}={payload}",
                                "payload": payload,
                                "expected": expected
                            })
                            self.results["vulnerabilities"].append({
                                "type": "SSTI",
                                "url": f"{self.url}?{param}={payload}",
                                "payload": payload,
                                "severity": "critical",
                                "issue": f"SSTI détectée via paramètre '{param}' — moteur de template vulnérable"
                            })
                            print(f"  [!!!] SSTI confirmée: paramètre '{param}'")
                            return
                except:
                    continue
        
        print(f"  [✓] Aucune SSTI confirmée")
        
    except Exception as e:
        print(f"  [✗] Erreur SSTI: {str(e)[:80]}")
