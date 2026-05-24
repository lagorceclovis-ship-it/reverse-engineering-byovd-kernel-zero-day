# Analyse d'une chaîne de chargement de driver kernel par BYOVD

**Auteur :** Clovis Lagorce
**Date :** Mai 2026
**Contact :** lagorceclovis@gmail.com
**Cadre :** Recherche personnelle en sécurité — Responsible Disclosure

> © 2026 Clovis Lagorce. Tous droits réservés.
> Reproduction partielle ou totale interdite sans autorisation écrite.
> Ce document a été horodaté avant publication.

---

## Avertissement

Cette analyse a été conduite sur un binaire obtenu à des fins de recherche uniquement. Aucune utilisation malveillante des techniques décrites n'a été réalisée. Les découvertes ont été transmises à l'éditeur concerné dans le cadre d'un responsible disclosure. Les indicateurs techniques spécifiques (hashes, URLs, pseudonymes, noms de drivers) ont été volontairement omis de ce document public et réservés au rapport de divulgation privé.

---

## Résumé

Ce write-up documente l'analyse d'un binaire Windows x86-64 protégé par VMProtect. L'analyse a révélé une chaîne de chargement de driver kernel en plusieurs étapes, exploitant une technique BYOVD (Bring Your Own Vulnerable Driver) pour contourner le DSE (Driver Signature Enforcement), et chargeant in fine un driver kernel custom non signé. Le sample malveillant était inconnu de l'ensemble des moteurs antivirus au moment de la soumission. Le binaire présente par ailleurs des indicateurs cohérents avec des techniques d'accès mémoire physique destinées à contourner une solution anti-cheat commerciale opérant en user-mode.

Ce document distingue explicitement les observations confirmées, les inférences raisonnables, et les hypothèses non vérifiées.

---

## Environnement et outils

| Outil | Usage |
|---|---|
| IDA Free 8.x | Analyse statique, extraction de chaînes, références croisées |
| x64dbg (dernière version) | Analyse dynamique, attachement de processus, dump mémoire |
| Plugin ScyllaHide | Contournement anti-debug (profil VMProtect) |
| PowerShell 5.1 | Extraction automatisée de chaînes, forensique registre |
| Python 3.x | Parsing binaire, extraction ASCII/UTF-16 |
| VirusTotal | Recherche de réputation du sample |

L'analyse a été conduite sur un système Windows 10 x64 isolé.

---

## 1. Analyse statique

### 1.1 Observations

Le binaire fait environ 12 MB et cible l'architecture x86-64. Lors du chargement dans IDA Free, l'auto-analyse entre en boucle sur une plage d'adresses particulière, empêchant toute complétion normale. Ce comportement est cohérent avec la virtualisation VMProtect, qui substitue les instructions natives par un bytecode propriétaire exécuté par une machine virtuelle embarquée.

La tentative de décompilation Hex-Rays sur la fonction d'entrée identifiée échoue avec le message suivant :

```
Error: stack frame is too big
```

L'inspection des métadonnées de la fonction révèle un stack frame déclaré anormalement large. Il s'agit d'une technique documentée de VMProtect qui gonfle artificiellement la taille du frame pour dépasser les limites du décompilateur.

### 1.2 Limites de l'analyse statique

En raison de la protection VMProtect, les éléments suivants n'ont pas pu être déterminés de manière fiable par analyse statique :

- Valeurs des chaînes déchiffrées à l'exécution (dont les endpoints réseau)
- Flot de contrôle précis des fonctions virtualisées
- Liste complète des APIs résolues à l'exécution

---

## 2. Analyse dynamique

### 2.1 Observations anti-debug

À l'exécution sous débogueur, le binaire affiche une alerte indiquant la détection d'un débogueur. Trois mécanismes distincts ont été identifiés :

1. Vérification via API Windows standard (user-mode)
2. Inspection directe du champ PEB.BeingDebugged, contournant la couche API
3. Vérifications supplémentaires apparemment implémentées au sein de la machine virtuelle VMProtect, résistantes aux approches de hooking classiques

### 2.2 Méthodologie de contournement

Le binaire a été lancé sans débogueur. x64dbg a ensuite été attaché au processus en cours d'exécution avec le plugin ScyllaHide configuré en profil VMProtect. Cette approche est efficace contre les mécanismes (1) et (2). Le mécanisme (3) avait déjà été exécuté au moment de l'attachement.

**Note :** Cette méthodologie ne garantit pas un contournement complet de l'anti-debug.

---

## 3. Acquisition mémoire et analyse des chaînes

### 3.1 Dump mémoire

Avec le débogueur attaché et le processus en attente d'une entrée utilisateur, un instantané mémoire des sections PE a été acquis depuis la console x64dbg. Taille du dump : environ 21 MB. À ce stade, les chaînes chiffrées par VMProtect présentes dans ces sections sont déjà déchiffrées en mémoire.

### 3.2 Extraction des chaînes

Un script Python a extrait toutes les séquences imprimables ASCII et UTF-16 LE de longueur minimale 5 depuis le dump. Total extrait : environ 23 700 chaînes, dont environ 300 correspondant à des mots-clés pertinents pour la sécurité.

### 3.3 Découvertes notables

**Chemins de symboles de debug (PDB) :**
Deux chemins PDB ont été identifiés dans le dump. Les chemins PDB sont des artefacts générés par le compilateur, embarquant le chemin du système de fichiers source au moment de la compilation. Leur présence dans un binaire distribué indique que les symboles de debug n'ont pas été supprimés. Les chemins suggèrent deux composants compilés sur des machines de développement, et incluent des pseudonymes embarqués dans les chemins de fichiers.

**Chaînes de messages d'erreur :**
Plusieurs chaînes suggèrent la présence d'un mécanisme de désactivation du DSE avec gestion d'erreurs. Les messages référencent des conditions d'échec pour les opérations d'activation et de désactivation du DSE, ainsi qu'une chaîne d'usage en ligne de commande acceptant un chemin de driver cible en argument.

**Références à des fonctions kernel :**
Trois chaînes de type log/debug ont été identifiées :

```
[DRIVER] BruteforceCR3: FOUND CR3=0x%llX
[DRIVER] ReadFunc: MmMapIoSpaceEx
PsGetProcessSectionBaseAddress
```

Ces chaînes semblent être des messages de debug embarqués dans le composant driver kernel. Leur présence suggère, sans le prouver de manière conclusive, l'utilisation de ces techniques à l'exécution.

---

## 4. Infrastructure réseau

### 4.1 Méthodologie

L'URL du serveur de licence était absente du dump mémoire en clair, indiquant un déchiffrement à l'exécution. L'analyse du cache DNS a été utilisée en alternative :

1. Vidage du cache résolveur DNS
2. Exécution du binaire avec soumission d'une entrée de test
3. Inspection du cache DNS pour de nouvelles entrées

### 4.2 Observations

Un sous-domaine d'une plateforme Backend-as-a-Service connue est apparu dans le cache après exécution. Ce sous-domaine contient un identifiant de projet unique qui permettrait au prestataire d'associer le projet à un compte enregistré, facilitant une identification par voie légale appropriée.

Les adresses IP résolues appartiennent à un prestataire CDN majeur agissant comme proxy inverse, masquant l'infrastructure backend réelle.

*Le domaine complet, l'identifiant de projet et les adresses IP sont omis et réservés au rapport de divulgation privé.*

---

## 5. Chaîne de chargement du driver kernel

### 5.1 Artefacts observés

**Système de fichiers :**
- Un ou plusieurs fichiers `.sys` aux noms hexadécimaux générés aléatoirement, déposés dans un répertoire temporaire accessible en écriture par l'utilisateur
- Un second fichier `.sys` déposé dans un répertoire temporaire système (supprimé ensuite ; artefacts registre subsistants)

**Registre Windows :**
Des services ont été créés sous `HKLM\SYSTEM\CurrentControlSet\Services` pour chaque fichier `.sys`. Propriétés clés :

```
Type  : 0x1  (SERVICE_KERNEL_DRIVER)
Start : 0x4  (SERVICE_DISABLED)
```

La valeur `SERVICE_DISABLED` définie après chargement est cohérente avec une tentative de réduction de la visibilité forensique.

### 5.2 Chaîne inférée

**La séquence de chargement des drivers n'a pas été observée directement à l'exécution**, en raison d'une validation de licence empêchant l'exécution complète avec des entrées de test. Ce qui suit est inféré depuis les artefacts système de fichiers, registre, et chaînes extraites.

**Étape 1 — Driver légitime vulnérable :**
Un driver signé par un éditeur logiciel légitime est chargé. Ce driver est référencé dans la base LOLDrivers et est connu pour exposer des primitives de lecture/écriture mémoire kernel via des interfaces IOCTL. Sa signature légitime lui permet de se charger sous l'application normale du DSE.

**Étape 2 — Bypass DSE :**
Le driver vulnérable est utilisé pour modifier une variable d'application kernel. Cette inférence est appuyée par les chaînes d'erreur extraites référençant des opérations DSE.

**Étape 3 — Chargement du driver custom :**
Un driver portant un certificat WDK de test est chargé. Sur un système où `testsigning` est désactivé (confirmé via bcdedit), un tel certificat empêcherait normalement le chargement. Sa présence constitue une preuve indirecte d'un bypass DSE préalable.

**Étape 4 — Nettoyage :**
Fichier du driver vulnérable supprimé du disque. Entrées de service mises en DISABLED dans le registre.

*Noms précis des drivers, codes IOCTL et adresses kernel omis.*

---

## 6. Sample du driver custom

### 6.1 Signature Authenticode

Les fichiers `.sys` custom portent la signature suivante (résumée) :

```
Type de certificat : WDK Test Certificate (usage développement uniquement)
Common Name        : "WDKTestCert [pseudonyme], [numéro de série]"
```

Un WDKTestCert est auto-signé et généré localement avec le Windows Driver Kit. Il est destiné exclusivement au développement. Windows refuse les drivers portant ce type de certificat sauf si le système est en mode test signing ou si le DSE a été bypassé. Le champ Common Name contient un pseudonyme de développeur — une défaillance de sécurité opérationnelle constituant un indicateur d'attribution.

### 6.2 Résultat VirusTotal

Hash SHA-256 soumis à VirusTotal : **0 détection sur 72 moteurs** au moment de la soumission.

Il s'agit d'une observation ponctuelle. Elle n'implique pas une capacité d'évasion permanente, et le taux de détection peut évoluer suite aux notifications transmises aux éditeurs.

*Hash omis de ce document public.*

---

## 7. Accès mémoire physique

### 7.1 Contexte

Le binaire semble ciblé sur un processus protégé par une solution anti-cheat commerciale opérant principalement en user-mode, surveillant les APIs Windows standard d'accès mémoire.

### 7.2 Indicateurs observés

Les chaînes suivantes extraites du dump suggèrent des techniques d'accès mémoire physique. **Celles-ci n'ont pas été confirmées par observation directe à l'exécution.**

```
[DRIVER] BruteforceCR3: FOUND CR3=0x%llX
[DRIVER] ReadFunc: MmMapIoSpaceEx
PsGetProcessSectionBaseAddress
```

**Registre CR3 :** En architecture x86-64, le registre CR3 contient l'adresse physique de base du répertoire de pages du processus actif. L'énumération des valeurs CR3 est une technique documentée pour localiser l'espace mémoire physique d'un processus cible sans utiliser les APIs mémoire virtuelle surveillées.

**MmMapIoSpaceEx :** API kernel Windows mappant une plage d'adresses physiques en espace d'adressage virtuel, normalement utilisée pour l'accès matériel. Son usage ici, combiné à une approche d'énumération CR3, est cohérent avec des techniques de lecture mémoire physique documentées dans la littérature de recherche en sécurité.

**PsGetProcessSectionBaseAddress :** Retourne l'adresse de base de l'image exécutable d'un processus, utilisée pour localiser le processus cible en mémoire.

### 7.3 Évaluation

Si implémentée comme suggéré par les chaînes extraites, cette approche opèrerait entièrement en kernel-mode et ne générerait pas les appels API user-mode surveillés par la solution anti-cheat observée. Toutefois, **cela n'a pas été confirmé par observation directe à l'exécution**.

---

## 8. Indicateurs d'attribution

Aucune investigation active (OSINT, énumération de comptes) n'a été conduite. Deux indicateurs passifs ont été identifiés :

| Type d'indicateur | Observation |
|---|---|
| Chemin PDB dans le binaire | Pseudonyme A : composant "GDRVLoader" compilé sur un bureau personnel |
| Common Name Authenticode | Pseudonyme B : certificat WDK de test généré par le développeur du driver |

Un développement à deux personnes est suggéré, bien qu'un développeur unique utilisant plusieurs pseudonymes ne puisse être exclu.

*Pseudonymes complets réservés au rapport de divulgation privé.*

---

## 9. Limites de l'analyse

- **Exécution incomplète.** La validation de licence a empêché l'exécution complète. Le chargement des drivers et l'accès mémoire physique n'ont pas été observés directement. Les conclusions des sections 5 et 7 sont des inférences.
- **Couverture mémoire partielle.** Le dump couvre uniquement les sections PE. La heap et la stack n'ont pas été capturées.
- **Absence de débogage kernel.** Le comportement du driver est inféré depuis des chaînes extraites, non depuis une exécution observée.
- **Sample unique, exécution unique.** Le comportement peut varier selon les versions ou configurations système.
- **Instantané VirusTotal.** Le taux de détection reflète un moment précis dans le temps.

---

## 10. Synthèse des découvertes

| Découverte | Niveau de confiance | Base |
|---|---|---|
| Obfuscation VMProtect | Élevé | Analyse statique |
| Anti-debug multicouche | Élevé | Observation dynamique |
| Dump mémoire — 21 MB, 23 700+ chaînes | Élevé | Artefact direct |
| Domaine C2 identifié | Élevé | Cache DNS |
| Fichiers .sys dans %TEMP% | Élevé | Système de fichiers |
| Services driver kernel dans le registre | Élevé | Registre |
| WDKTestCert avec pseudonyme développeur | Élevé | Signature Authenticode |
| 0/72 VirusTotal à la soumission | Élevé | Rapport VirusTotal |
| Bypass DSE | Moyen | Indirect — testsigning=No + WDKTestCert chargé |
| Chaîne BYOVD | Moyen | Artefacts chaînes + registre |
| Accès mémoire physique | Moyen | Artefacts chaînes uniquement — non confirmé à l'exécution |
| Attribution deux développeurs | Faible-Moyen | Chemin PDB + CN certificat |

---

## 11. Responsible Disclosure

Les découvertes ont été transmises à l'éditeur concerné, incluant les indicateurs techniques complets omis ici. Les éditeurs antivirus ont été notifiés pour création de signatures de détection.

---

## Références

- Projet LOLDrivers — loldrivers.io — Base de données des drivers vulnérables
- MITRE ATT&CK : T1014 (Rootkit), T1068, T1562.001
- Microsoft — Documentation Driver Signature Enforcement, WDK Test Certificates
- Recherche publique sur la lecture mémoire physique via CR3/MmMapIoSpaceEx

---

*© 2026 Clovis Lagorce — lagorceclovis@gmail.com*
*Reproduction interdite sans autorisation écrite.*
*IDA Free · x64dbg · ScyllaHide · PowerShell · Python · VirusTotal*
