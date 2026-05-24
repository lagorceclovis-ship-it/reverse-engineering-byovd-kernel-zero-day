# Reverse Engineering — BYOVD & Kernel Zero-Day Discovery

**Auteur : Clovis Lagorce** | Mai 2026 | lagorceclovis@gmail.com

> (c) 2026 Clovis Lagorce. Reproduction interdite sans autorisation ecrite.  
> Ce write-up a ete horodate avant publication.

---

## Resume

Durant une session d analyse de retro-ingenierie, j ai identifie un binaire malveillant implementant une chaine d attaque kernel avancee : exploitation BYOVD, chargement d un driver Ring 0 zero-day, et bypass structurel d une solution anti-cheat commerciale via acces memoire physique direct. Le driver malveillant decouvert etait **inconnu de l ensemble des moteurs antivirus** au moment de l analyse (0/72 VirusTotal).

Ce document presente mes decouvertes dans une optique de responsible disclosure. Certains details techniques ont ete volontairement omis.

---

## 1. Le binaire

Executable Windows x86-64, ~12 MB, protege par **VMProtect**. Lors du chargement dans IDA Free, l auto-analyse entre en boucle infinie — caracteristique de la virtualisation VMProtect. Tentative de decompilation Hex-Rays : echec. Stack frame artificiellement gonfle a **126 MB** pour neutraliser le decompilateur.

---

## 2. Contournement de l anti-debug

Trois couches de protection identifiees :
- API Windows standard (IsDebuggerPresent)
- Lecture directe du PEB (PEB.BeingDebugged)
- Verifications virtualisees VMProtect, non hookables par les outils classiques

Strategie : **attachement au processus apres demarrage** avec ScyllaHide (profil VMProtect).

---

## 3. Extraction des chaines memoire

VMProtect chiffre les chaines — elles ne sont dechiffrees qu a l execution. Dump de **21 MB** realise depuis le debogueur attache. Extraction : **23 730 chaines** dont **300 significatives** filtrees par mots-cles.

Decouverte cle : chemin de compilation contenant le **pseudonyme d un developpeur** laisse par inadvertance dans les symboles de debug.

---

## 4. Infrastructure C2

URL du serveur chiffree dans le binaire. Methode : analyse du **cache DNS** avant/apres execution. Serveur identifie : backend-as-a-service masque derriere un CDN. L identifiant unique du projet permet une identification legale du createur de compte.

*Details reserves au rapport de responsible disclosure.*

---

## 5. BYOVD — Chaine d attaque kernel

Apres execution, decouverte de **fichiers .sys aux noms aleatoires** dans %TEMP% et de services kernel dans le registre :



**Temps 1** — Driver legitime signe charge via une vulnerabilite IOCTL permettant des ecritures arbitraires en memoire kernel.

**Temps 2** — Exploitation pour desactiver le **DSE (Driver Signature Enforcement)**. Driver malveillant charge en Ring 0 sans signature valide.

Preuve : testsigning desactive, driver WDKTestCert charge quand meme = DSE bypass confirme.

---

## 6. Driver zero-day

Signature Authenticode du driver :



- Le **pseudonyme de l auteur** est inscrit dans son propre certificat de developpement
- Soumis VirusTotal : **0/72 detections**
- Nom genere aleatoirement a chaque run pour contourner les signatures statiques

**Zero-day confirme.**

---

## 7. Bypass — Pourquoi c est indetectable

La solution anti-cheat opere en Ring 3. Le driver en Ring 0, sous son niveau de supervision. Trois fonctions kernel identifiees dans le dump :

- **BruteforceCR3** : identifie l espace memoire physique du processus cible via brute force du registre CR3
- **MmMapIoSpaceEx** : mappe directement des pages physiques sans passer par les APIs surveillees
- **PsGetProcessSectionBaseAddress** : localise l executable cible en memoire

Aucun appel API tracable. Indetectable structurellement depuis le user-mode.

---

## 8. Attribution

| Role | Preuve |
|---|---|
| Auteur du driver kernel zero-day | Pseudonyme dans le certificat Authenticode |
| Auteur du composant BYOVD | Chemin PDB dans le binaire |

---

## 9. Implications

Ces techniques — BYOVD, DSE bypass, acces memoire physique Ring 0 — sont les memes que celles utilisees par :

- **AuKill / LockBit** : BYOVD pour desactiver les EDR avant ransomware
- **Lazarus Group** : drivers non signes pour cyberespionnage  
- **Industroyer** : acces kernel pour sabotage industriel

---

## Synthese des preuves

| Element | Statut |
|---|---|
| VMProtect identifie et contourne | Confirme |
| Anti-debug multicouche bypasse | Confirme |
| 300+ chaines extraites depuis dump memoire | Confirme |
| Serveur C2 identifie | Confirme |
| Chaine BYOVD complete documentee | Confirme |
| Driver zero-day (0/72 VirusTotal) | Confirme |
| DSE bypass prouve | Confirme |
| Bypass EAC (CR3 + MmMapIoSpaceEx) | Confirme |
| Attribution 2 developpeurs | Confirme |
| Responsible disclosure redige | Confirme |

---

## Conclusion

Ce projet illustre qu un acteur isole peut construire une chaine d attaque complete contournant les protections modernes de Windows et rester indetectable. L ensemble des preuves a ete transmis a l editeur et aux editeurs antivirus dans le cadre d un responsible disclosure.

---

*(c) 2026 Clovis Lagorce — lagorceclovis@gmail.com*  
*IDA Free · x64dbg · ScyllaHide · PowerShell · Python · VirusTotal*
