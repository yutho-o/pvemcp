# pvemcp

Serveur [MCP](https://modelcontextprotocol.io) pour [Proxmox VE](https://www.proxmox.com/proxmox-ve) : il permet à un agent IA de consulter et de piloter un cluster par son API et, si vous l'autorisez, par SSH.

- **Toute l'API, prouvée par un test.** Le schéma officiel compte 680 méthodes. Chacune a son outil généré au démarrage (`pve_list_vms`, `pve_start_lxc`, `pve_update_vm_config`…), sauf 12 listées dans le code avec leur raison, dont 11 bloquées par la politique d'accès et l'envoi de fichier, qui a son propre outil.
- **SSH et LXC.** L'API ne sait pas exécuter une commande dans un conteneur : 53 outils passent par `pct` sur le nœud, avec vérification de la clé d'hôte. C'est désactivé par défaut.
- **Lecture seule par défaut.** Sans autorisation explicite, les outils d'écriture ne sont même pas proposés.
- **Un seul point de contrôle.** Toute requête passe par la politique d'accès du client HTTP, y compris `pve_api_write` et les outils composés. Un chemin inconnu du catalogue compte comme sensible ou élevé.
- **Des outils composés** pour ce qu'on fait vraiment : audit, couverture des sauvegardes, création d'un conteneur, attente d'une tâche.

> **État du projet.** Ce serveur n'a jamais parlé à un vrai Proxmox. Les tests tournent contre des faux serveurs : un serveur HTTP construit d'après le schéma officiel de l'API, et un vrai serveur SSH local où `pct` est un script qui exécute ce qu'on lui donne. Le schéma décrit les noms et les types, pas tout le comportement réel. **Commencez en lecture seule, avec un jeton limité, sur un cluster de test.** Pour une première écriture, passez par `PROXMOX_DRY_RUN=true`, et gardez un accès à l'interface web et à la console.

## Installation

Le serveur est un binaire Rust autonome, sans dépendance à l'exécution. Il faut Rust 1.88 ou plus récent pour le compiler.

```bash
cargo build --release
```

Le binaire est `target/release/pvemcp` (`pvemcp.exe` sous Windows). Le catalogue de l'API y est intégré : il peut être copié seul où l'on veut.

### Claude Code ou Claude Desktop

```json
{
  "mcpServers": {
    "proxmox": {
      "command": "C:/chemin/vers/pvemcp/target/release/pvemcp.exe",
      "env": {
        "PROXMOX_URL": "https://192.168.1.10:8006",
        "PROXMOX_CREDENTIALS_FILE": "C:/chemin/vers/pvemcp.token",
        "PROXMOX_FINGERPRINT": "AA:BB:CC:…"
      }
    }
  }
}
```

- **Claude Desktop** : ce bloc va dans `%APPDATA%\Claude\claude_desktop_config.json`.
- **Claude Code** : dans `.mcp.json` à la racine du projet, ou avec `claude mcp add-json proxmox '<le bloc>'`. Ne versionnez pas un `.mcp.json` qui contient un secret : `PROXMOX_CREDENTIALS_FILE` évite de l'y écrire.
- **Chemins Windows en JSON** : barres obliques (`C:/chemin/vers`) ou barres inverses doublées (`C:\\chemin\\vers`).

Le fichier de `PROXMOX_CREDENTIALS_FILE` contient une seule ligne `mcp@pve!pvemcp=<secret>`, ou des lignes `token_id=`, `token_secret=`. Vous trouverez aussi [`examples/mcp.json`](examples/mcp.json).

### Certificat

Proxmox utilise par défaut un certificat signé par l'autorité du cluster. Trois possibilités, de la meilleure à la pire :

| Option | Valeur | Quand |
|---|---|---|
| `PROXMOX_CA_FILE` | copie de `/etc/pve/pve-root-ca.pem` | La vérification reste complète, si l'adresse de `PROXMOX_URL` figure dans le certificat |
| `PROXMOX_FINGERPRINT` | empreinte SHA-256 donnée par `pvenode cert info` sur le nœud | Épingle ce certificat. À refaire à son renouvellement |
| `PROXMOX_VERIFY_SSL=false` | | Aucune vérification : à réserver à un réseau de confiance |

### Créer le jeton API

Sur un nœud, en root :

```bash
pveum user add mcp@pve --comment "pvemcp"
pveum user token add mcp@pve pvemcp --privsep 1 --comment "pvemcp"
```

La seconde commande affiche `full-tokenid` et `value`. **La valeur n'apparaît qu'une fois.** La configuration attend `PROXMOX_TOKEN=mcp@pve!pvemcp=<value>`. L'option `--expire <secondes depuis 1970>` fixe une date de fin, ce que `pve_security_audit` vous conseillera.

**Avec `--privsep 1`, qui est le défaut, le jeton n'a que l'intersection de ses droits et de ceux de l'utilisateur.** Il faut donc donner le rôle aux deux, sinon le jeton ne voit rien, et une liste peut revenir vide plutôt qu'en erreur :

```bash
pveum acl modify / --users mcp@pve --roles PVEAuditor
pveum acl modify / --tokens 'mcp@pve!pvemcp' --roles PVEAuditor
pveum user token permissions mcp@pve pvemcp
```

Les guillemets simples protègent le `!` du shell. La dernière commande montre les droits effectifs du jeton.

`--privsep 0` donnerait au jeton tous les droits de l'utilisateur : à éviter.

| Usage | Rôles à donner à l'utilisateur **et** au jeton |
|---|---|
| Lecture de tout le cluster | `PVEAuditor` sur `/` |
| Journaux des nœuds | ajouter le privilège `Sys.Syslog` (dans `PVESysAdmin`, qui donne aussi la console du nœud) |
| Machines et conteneurs | `PVEVMAdmin` sur `/vms`, `PVEDatastoreUser` sur `/storage`, `PVESDNUser` sur `/sdn/zones` pour brancher les réseaux |
| Presque tout, sauf système et droits | `PVEAdmin` sur `/` |
| Exécuter par l'agent QEMU | `VM.GuestAgent.*`, compris ou non dans vos rôles selon la version de Proxmox |

Ces combinaisons viennent de la documentation de Proxmox et n'ont pas été éprouvées sur un vrai cluster. Une erreur `forbidden` indique le privilège attendu, repris du schéma. `pve_security_audit` signale les sections qu'il n'a pas pu lire au lieu de les déclarer conformes.

Quelques méthodes refusent tout jeton (mot de passe, double facteur) et sont refusées avant envoi avec un message clair. La documentation de Proxmox ajoute que les consoles ne sont pas accessibles par jeton : les outils de la porte `console` demanderont probablement `PROXMOX_USERNAME` et `PROXMOX_PASSWORD`. Une connexion par mot de passe ne gère pas le double facteur : un compte qui l'exige donne une erreur demandant d'utiliser un jeton.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `PROXMOX_URL` | | Adresse de l'API. Le port 8006 est ajouté s'il manque |
| `PROXMOX_TOKEN` | | Jeton complet : `utilisateur@realm!id=secret` |
| `PROXMOX_TOKEN_ID`, `PROXMOX_TOKEN_SECRET` | | Ou le jeton en deux parties |
| `PROXMOX_CREDENTIALS_FILE` | | Ou un fichier qui contient le jeton |
| `PROXMOX_USERNAME`, `PROXMOX_PASSWORD` | | Ou une connexion par mot de passe, avec le realm : `root@pam` |
| `PROXMOX_VERIFY_SSL` | `true` | Vérification du certificat |
| `PROXMOX_CA_FILE` | | Autorité à laquelle faire confiance |
| `PROXMOX_FINGERPRINT` | | Empreinte SHA-256 du certificat attendu |
| `PROXMOX_ALLOW_WRITES` | `false` | Voir [Portes](#portes-et-options) |
| `PROXMOX_ALLOW_ELEVATED` | `false` | Voir [Portes](#portes-et-options) |
| `PROXMOX_ALLOW_GUEST_EXEC` | `false` | Voir [Portes](#portes-et-options) |
| `PROXMOX_ALLOW_SSH` | `false` | Voir [Portes](#portes-et-options) |
| `PROXMOX_ALLOW_SENSITIVE` | `false` | Voir [Portes](#portes-et-options) |
| `PROXMOX_DRY_RUN` | `false` | Propose les outils d'écriture, mais n'envoie rien et montre ce qui serait envoyé |
| `PROXMOX_TOOLSETS` | tout sauf `sdn`, `ceph`, `notifications`, `acme`, `mapping` | Domaines à charger, ou `all` |
| `PROXMOX_DEFAULT_NODE` | | Nœud pris quand un outil sans `vmid` n'en reçoit pas. Sinon, le seul nœud du cluster |
| `PROXMOX_PROTECTED_VMIDS` | | Invités à ne pas modifier : `100,101`. Voir [ses limites](#ce-qui-nest-pas-protégé) |
| `PROXMOX_UNBLOCK` | | Méthodes bloquées à autoriser : `POST /nodes/{node}/execute`, ou `/access/ticket` pour toutes celles de ce chemin |
| `PROXMOX_TIMEOUT_SECONDS` | `30` | Délai d'une requête (1 à 3600) |
| `PROXMOX_TASK_WAIT_SECONDS` | `30` | Attente d'une tâche par un outil (0 à 3600) |
| `PROXMOX_ELICIT` | `true` | Demande une confirmation humaine avant une action destructive, si le client sait le faire |
| `PROXMOX_AUDIT_LOG` | | Fichier JSONL qui journalise les écritures, les commandes SSH et les refus |
| `PROXMOX_MAX_RESPONSE_CHARS` | `120000` | Taille maximale d'une réponse (2000 à 5000000) |
| `PROXMOX_LOCAL_DIR` | | Seul dossier local permis pour les transferts de fichiers. Sans lui, ils sont refusés |
| `PROXMOX_CONFIG` | | Fichier décrivant plusieurs clusters |
| `PROXMOX_MCP_TOKEN` | | Jeton Bearer du mode `--http`. Obligatoire hors de la boucle locale |
| `PROXMOX_MCP_ALLOWED_HOSTS` | | Valeurs de plus acceptées dans l'en-tête `Host`, pour un proxy |

Et pour SSH :

| Variable | Défaut | Rôle |
|---|---|---|
| `PROXMOX_SSH_USER` | `root` | Utilisateur sur les nœuds |
| `PROXMOX_SSH_PORT` | `22` | Port des nœuds |
| `PROXMOX_SSH_KEY_FILE` | | Clé privée |
| `PROXMOX_SSH_KEY_PASSPHRASE` | | Sa phrase de passe |
| `PROXMOX_SSH_PASSWORD` | | Ou un mot de passe |
| `PROXMOX_SSH_AGENT` | | Ou un agent : socket, `pageant`, ou `\\.\pipe\openssh-ssh-agent` sous Windows (ces deux derniers n'ont pas été essayés) |
| `PROXMOX_SSH_NODES` | | Nœuds et adresses : `pve1=10.0.0.11,pve2=10.0.0.12`, ou en JSON. Sinon l'adresse donnée par `/cluster/status`, ou celle de l'API s'il n'y a qu'un nœud |
| `PROXMOX_SSH_SUDO` | `false` | Préfixe les commandes de `sudo -n` si l'utilisateur n'est pas root |
| `PROXMOX_SSH_KNOWN_HOSTS` | `~/.ssh/known_hosts` | Fichier des clés d'hôtes |
| `PROXMOX_SSH_HOST_KEY_POLICY` | `strict` | `strict` refuse un hôte inconnu, `accept-new` l'ajoute au fichier, `off` ne vérifie plus |
| `PROXMOX_SSH_FINGERPRINTS` | | Clés épinglées : `pve1=SHA256:…`, ou en JSON. Respectées même avec `off` |
| `PROXMOX_SSH_TIMEOUT_SECONDS` | `120` | Délai d'une commande |
| `PROXMOX_SSH_MAX_OUTPUT_BYTES` | `1048576` | Sortie conservée par commande. Au-delà, `truncated: true` |
| `PROXMOX_GUEST_SSH_USER` | `root` | Utilisateur pour le SSH direct vers un invité |
| `PROXMOX_GUEST_SSH_KEY_FILE`, `PROXMOX_GUEST_SSH_PASSWORD` | | Ses identifiants |

Une faute de frappe dans une option de sécurité (`PROXMOX_ALLOW_WRITES=ture`) arrête le serveur plutôt que d'appliquer une valeur par défaut. Les journaux vont sur stderr : stdout ne porte que le protocole MCP.

### Plusieurs clusters

`PROXMOX_CONFIG` pointe vers un fichier comme [`examples/instances.json`](examples/instances.json). Les valeurs `${VARIABLE}` sont lues dans l'environnement, ce qui évite d'y écrire les secrets. Chaque outil reçoit alors un paramètre `instance`, et les droits se règlent par cluster, avec les mêmes noms en minuscules (`allow_writes`, `protected_vmids`, `local_dir`, et `ssh: { key_file, nodes, fingerprints… }`). Une variable `PROXMOX_*` sert de valeur par défaut. Un outil est proposé si au moins un cluster l'autorise, et chaque appel est vérifié pour le sien.

### Mode HTTP

```bash
pvemcp --http --host 127.0.0.1 --port 8765
```

Le point d'accès est `/mcp`. Voir [Accès réseau](#accès-réseau).

## Portes et options

Chaque outil et chaque requête relèvent d'une porte. Un outil dont la porte est fermée pour tous les clusters n'est pas proposé, et la requête serait refusée de toute façon par le client HTTP.

| Porte | Outils | Il faut | Ce qu'elle ouvre |
|---|---:|---|---|
| `read` | 327 | rien | Lectures ordinaires |
| `sensitive` | 21 | `ALLOW_SENSITIVE` | Lectures qui rendent des secrets ou contactent ailleurs : rapport de nœud, export de métriques, configuration Ceph, plugins ACME, informations pour rejoindre le cluster, lecture de fichier par l'agent QEMU, contenu d'une sauvegarde, scans CIFS, NFS, iSCSI, PBS |
| `write` | 113 | `ALLOW_WRITES` ou dry run | Changer et piloter les invités : créer, cloner, configurer, démarrer, arrêter, instantanés, sauvegardes, HA, pare-feu d'un invité, pools |
| `elevated` | 209 | `ALLOW_WRITES` ou dry run, **et** `ALLOW_ELEVATED` | Changer le cluster lui-même : comptes et droits, stockages, réseau, SDN, pare-feu du cluster et des nœuds, Ceph, certificats, disques, services, alimentation d'un nœud, actions groupées |
| `guest_exec` | 7 | `ALLOW_GUEST_EXEC`, plus `ALLOW_WRITES` ou dry run sauf pour lire un résultat | Exécuter dans une VM par l'agent QEMU, écrire un fichier, changer un mot de passe, moniteur QEMU, touches envoyées à la console |
| `console` | 10 | `ALLOW_WRITES`, `ALLOW_ELEVATED` et `ALLOW_SENSITIVE`, jamais le dry run | Tickets VNC, SPICE et terminal : ils valent une connexion |
| `ssh_read` | 20 | `ALLOW_SSH` | Commandes fixes en lecture sur les nœuds et dans les conteneurs. **Lit presque tous les fichiers, en root.** Voir [Sécurité](#sécurité) |
| `ssh_write` | 33 | `ALLOW_SSH`, et `ALLOW_WRITES` ou dry run | Tout le reste en SSH, dont l'exécution de n'importe quelle commande en root |
| `blocked` | | listé dans `PROXMOX_UNBLOCK`, puis comme `elevated` | Ce qui contournerait la politique ou ne tient pas dans un appel d'outil : `POST /nodes/{node}/execute`, websockets de console, tunnels de migration, `/access/ticket`, connexion OpenID. Ces méthodes n'ont pas d'outil : une fois débloquée, une méthode autre que GET passe par `pve_api_write`. Un GET bloqué reste inaccessible |

**Certains arguments font monter la porte.** Sur un outil de la porte `write`, ils demandent en plus `ALLOW_ELEVATED`, car ils atteignent l'hôte : `hookscript`, `args`, `hostpci[n]`, `parallel[n]`, `usb[n]` avec `host=`, `serial[n]` autre que `socket` pour une VM ; `hookscript`, `dev[n]`, `mp[n]` ou `rootfs` sur un chemin de l'hôte pour un conteneur ; `script`, `dumpdir`, `tmpdir` pour une sauvegarde.

**Un conteneur privilégié demande `ALLOW_ELEVATED`, y compris par omission** : sans `unprivileged=1`, Proxmox en crée un privilégié, et une restauration reprend le réglage de la sauvegarde. `pve_provision_lxc` envoie `unprivileged=1` par défaut.

**Confirmation humaine.** Les outils destructifs posent la question avant d'agir, si le client MCP sait le faire (`elicitation`), et échouent si la question échoue : tout `DELETE`, arrêt forcé, retour à un instantané, formatage, arrêt d'un service, certaines valeurs d'argument (`purge`, `force` à la création, `unused[n]` dans `delete`, etc.). **Si le client ne le sait pas, rien n'est demandé** : il n'a que l'annotation `destructiveHint`. Il en va de même en mode HTTP. `PROXMOX_ELICIT=false` supprime la question.

## Outils

Chiffres tirés de `--list-tools`, tout activé, chaque outil compté dans son domaine principal. « Lecture » regroupe `read`, `sensitive` et `ssh_read`.

| Domaine | Lecture | Écriture | Contenu |
|---|---:|---:|---|
| `vm` | 28 | 43 | VM : configuration, état, instantanés, clonage, migration, agent QEMU, cloud-init, console |
| `lxc` | 14 | 22 | conteneurs par l'API : configuration, état, instantanés, clonage, migration, console |
| `node` | 40 | 26 | nœuds : état, services, journal, APT, certificats, DNS, alimentation |
| `storage` | 22 | 11 | stockages, contenu, téléchargement, envoi de fichier, scans |
| `backup` | 10 | 5 | vzdump, tâches de sauvegarde, restauration de fichiers, couverture |
| `tasks` | 5 | 1 | tâches : liste, état, journal, arrêt |
| `cluster` | 27 | 18 | cluster : état, ressources, options, réplication, journal, `nextid`, actions groupées |
| `ha` | 10 | 13 | haute disponibilité : ressources, règles, groupes, état |
| `firewall` | 41 | 45 | pare-feu du cluster, des nœuds et des invités : règles, alias, ipset, options |
| `access` | 20 | 27 | utilisateurs, groupes, rôles, ACL, realms, jetons, double facteur |
| `pools` | 2 | 5 | pools de ressources |
| `network` | 2 | 5 | interfaces des nœuds. Le DNS et le fichier hosts y sont aussi rattachés |
| `disks` | 8 | 10 | disques, LVM, ZFS, répertoires, effacement |
| `sdn` | 46 | 44 | SDN : zones, vnets, sous-réseaux, contrôleurs, fabrics (à activer) |
| `ceph` | 28 | 25 | Ceph : OSD, moniteurs, pools, CephFS, drapeaux (à activer) |
| `notifications` | 15 | 16 | points d'envoi, règles de notification (à activer) |
| `acme` | 10 | 9 | comptes et plugins ACME (à activer) |
| `mapping` | 7 | 9 | correspondances PCI, USB et répertoires (à activer) |
| `ssh` | 20 | 33 | SSH vers les nœuds, les conteneurs et les invités, terminaux |
| `workflows` | 9 | 4 | outils composés |
| `api` | 4 | 1 | catalogue, description d'une méthode, appels génériques, `pve_mcp_info` |

Soit 740 outils au total : 669 pour l'API, 5 génériques, 13 composés, 53 pour SSH. Un outil peut aussi être rattaché à un second domaine : `PROXMOX_TOOLSETS=lxc` charge ainsi `aplinfo`.

Pour afficher la liste exacte de votre configuration (domaine, porte, nom), sans aucune connexion :

```powershell
$env:PROXMOX_URL='https://pve:8006'; $env:PROXMOX_TOKEN='a@pam!b=c'; pvemcp --list-tools
```

**Attention à la taille.** Un client qui charge tous les outils dans son contexte les paie à chaque échange. Mesures de `tools/list` (la conversion en jetons est une estimation grossière, à 4 octets par jeton) :

| Configuration | Outils | Taille | Jetons environ |
|---|---:|---:|---:|
| Lecture seule, défaut | 228 | 208 Kio | 53 000 |
| Écritures, domaines par défaut | 341 | 503 Kio | 129 000 |
| Toutes les options, domaines par défaut | 531 | 792 Kio | 203 000 |
| Toutes les options, `PROXMOX_TOOLSETS=all` | 740 | 1038 Kio | 266 000 |
| `api,ssh`, `ALLOW_SSH` seul | 24 | 23 Kio | 6 000 |
| `api,ssh`, toutes les options | 58 | 67 Kio | 17 000 |
| `workflows,api`, lecture seule | 13 | 14 Kio | 3 500 |

**Le réglage conseillé pour commencer est `PROXMOX_TOOLSETS=workflows,api`** : 13 outils qui suffisent pour se repérer, et `pve_api_search`, `pve_api_describe`, `pve_api_read` et `pve_api_write` atteignent le reste de l'API, sous la même politique. Ajoutez ensuite `vm,lxc` ou `ssh` selon l'usage. `pve_create_vm` pèse à lui seul 25 Ko : toutes les options de Proxmox y sont décrites.

Le serveur fournit aussi des ressources (`proxmox://<instance>/cluster`, `nodes`, `guests`, `storage`, `tasks`) et six prompts : `cluster_health_review`, `troubleshoot_guest`, `provision_lxc`, `safe_guest_change`, `backup_review`, `security_review`.

### Comment écrire les arguments

- `node` peut être omis sur les outils d'invité : il se déduit du `vmid`. Sinon, il vaut `PROXMOX_DEFAULT_NODE` ou le seul nœud.
- Les paramètres numérotés s'écrivent `net0: "virtio,bridge=vmbr0"` ou `net: {"0": "virtio,bridge=vmbr0"}`.
- Comme Proxmox lit tout en texte, `1`, `"1"`, `true`, `on` et `yes` valent pour un booléen, et `"2048"` comme `2048` pour un nombre.
- **Un argument inconnu est refusé**, rien n'est envoyé, plutôt que d'être ignoré en silence.
- Les écritures qui lancent une tâche l'attendent par défaut (`wait`, `wait_seconds`). Une tâche échouée est une erreur. Une tâche trop longue répond `still_running` et continue : suivez-la avec `pve_wait_task`, sans la relancer.
- Toute écriture accepte `dry_run: true`. Attention, Proxmox ne valide qu'un vrai appel : un dry run ne prouve pas que les valeurs seraient acceptées.

## SSH et LXC

L'API de Proxmox n'exécute rien dans un conteneur. Tout passe donc par `pct` sur le nœud qui héberge le conteneur, sur une connexion SSH au nœud. **C'est root sur l'hyperviseur.** Lisez [Sécurité](#sécurité) avant d'activer.

### Mise en place

**1. Créer une clé réservée à ce serveur**, sur la machine qui l'exécute :

```powershell
ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\pvemcp -C pvemcp
Get-Content $env:USERPROFILE\.ssh\pvemcp.pub
```

Si vous lui donnez une phrase de passe, indiquez-la dans `PROXMOX_SSH_KEY_PASSPHRASE`, ou utilisez un agent avec `PROXMOX_SSH_AGENT`.

**2. L'installer sur chaque nœud**, depuis le shell de l'interface web :

```bash
echo 'ssh-ed25519 AAAA… pvemcp' >> /root/.ssh/authorized_keys
```

Sur un cluster, ce fichier peut être partagé entre les nœuds par `/etc/pve/priv/authorized_keys` : la clé vaut alors pour tous. Vérifiez avec `ls -l /root/.ssh/authorized_keys`.

**3. Noter l'empreinte de la clé d'hôte, par un canal de confiance.** Toujours depuis le shell de l'interface web, pas par une connexion SSH qu'il s'agit justement de vérifier :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

**4. L'enregistrer**, au choix :

- Par `known_hosts` : connectez-vous une fois, comparez l'empreinte affichée à celle de l'étape 3, et répondez `yes` seulement si elles sont identiques.

  ```powershell
  ssh -i $env:USERPROFILE\.ssh\pvemcp root@10.0.0.11 pveversion
  ```

  L'adresse doit être la même que dans `PROXMOX_SSH_NODES` : une entrée pour `10.0.0.11` ne vaut pas pour `pve1`.
- Ou par épinglage, sans fichier : `PROXMOX_SSH_FINGERPRINTS=pve1=SHA256:…`.

**5. Activer :**

```json
"PROXMOX_ALLOW_SSH": "true",
"PROXMOX_SSH_KEY_FILE": "C:/Users/vous/.ssh/pvemcp",
"PROXMOX_SSH_NODES": "pve1=10.0.0.11,pve2=10.0.0.12"
```

**6. Tester avec `pve_ssh_test`** (`{"node": "pve1"}`) : il se connecte, puis rend la clé d'hôte vérifiée, l'utilisateur et `pveversion`. Les erreurs possibles :

| Erreur | Sens |
|---|---|
| `host_key_unknown` | Clé absente de `known_hosts`. La réponse donne l'empreinte reçue : comparez-la à l'étape 3 **avant** de l'épingler |
| `host_key_mismatch` | La clé a changé. Connexion refusée, aucun identifiant envoyé. Réinstallation ou attaque : à vérifier avant tout |
| `ssh_auth_failed` | Clé ou utilisateur refusé |
| `ssh_unreachable` | Pas de connexion : adresse, port, pare-feu |

Sans root : `PROXMOX_SSH_USER=mcp`, `PROXMOX_SSH_SUDO=true`, avec une règle `NOPASSWD` pour `sudo -n`. Cela ne restreint rien si la règle laisse tout passer, et `pct` demande root de toute façon. SFTP ne passe pas par `sudo` : les transferts se font avec les droits de l'utilisateur.

### Outils

Sur les nœuds, en lecture : `pve_ssh_test`, `pve_ssh_host_diagnostics`, `pve_ssh_journal`, `pve_ssh_list_dir`, `pve_ssh_read_file`, `pve_ssh_pct_list`, `pve_ssh_qm_list`. En écriture : `pve_ssh_exec`, `pve_ssh_write_file`, `pve_ssh_upload`, `pve_ssh_download`, `pve_ssh_delete_file`.

Dans un conteneur, par `pct` (`vmid` obligatoire, nœud déduit) :

| | Lecture | Écriture |
|---|---|---|
| Système | `pve_lxc_info`, `pve_lxc_processes`, `pve_lxc_ports`, `pve_lxc_disk_usage`, `pve_lxc_logs` | `pve_lxc_exec`, `pve_lxc_run_script` |
| Fichiers | `pve_lxc_list_dir`, `pve_lxc_read_file` | `pve_lxc_write_file`, `pve_lxc_push_file`, `pve_lxc_pull_file`, `pve_lxc_delete_file` |
| Services | `pve_lxc_service_status` | `pve_lxc_service` |
| Paquets | `pve_lxc_list_packages` | `pve_lxc_install_packages`, `pve_lxc_remove_packages`, `pve_lxc_update_packages` |
| Comptes | `pve_lxc_list_users` | `pve_lxc_create_user`, `pve_lxc_delete_user`, `pve_lxc_set_password` |
| Disque | | `pve_lxc_fsck`, `pve_lxc_fstrim`, `pve_lxc_mount`, `pve_lxc_unmount` |
| sshd du conteneur | `pve_lxc_ssh_status`, `pve_lxc_ssh_list_keys` | `pve_lxc_ssh_enable`, `pve_lxc_ssh_disable`, `pve_lxc_ssh_add_key`, `pve_lxc_ssh_remove_key`, `pve_lxc_ssh_configure` |

Paquets, services et sshd reconnaissent Debian, Ubuntu, Alpine, la famille RHEL et Arch (apt, apk, dnf, yum, pacman ; systemd ou OpenRC). `pve_lxc_ssh_configure` teste avec `sshd -t` et restaure en cas d'échec.

SSH direct vers un invité : `pve_guest_ssh_test`, `pve_guest_ssh_exec`, avec `PROXMOX_GUEST_SSH_*`. L'adresse vient de Proxmox ou de `host`, et `via_node` passe par le nœud. Pour un conteneur, la clé d'hôte est lue par `pct`, un chemin déjà authentifié : rien à configurer. Pour une VM, il faut `known_hosts` ou l'argument `fingerprint`.

Terminaux pour les programmes interactifs : `pve_ssh_session_open` (`node` pour un shell du nœud, `vmid` pour `pct enter`), `pve_ssh_session_send`, `pve_ssh_session_read`, `pve_ssh_session_close`, `pve_ssh_session_list`. Huit au plus, fermés après 15 minutes sans activité et à l'arrêt du serveur, avec 1 Mio de sortie conservée. Seule l'ouverture demande confirmation : pas chaque touche.

### Ce que fait le serveur pour ces commandes

- Tout argument passe par une fonction de citation shell, testée avec des charges hostiles dans `dash` et `bash`. Les noms de paquets, de services et d'utilisateurs suivent une liste blanche, dont le premier caractère bloque l'injection d'options.
- Un mot de passe (`pve_lxc_set_password`) passe par stdin, jamais sur la ligne de commande. `stdin` et le contenu des fichiers ne sont pas journalisés. Les valeurs d'`env` restent visibles sur la ligne de commande du nœud pendant l'exécution.
- Les sorties sont nettoyées des séquences ANSI, des caractères de contrôle et des clés PEM, et marquées `untrusted: true`.
- Un code de retour non nul est un résultat, pas une erreur. Une sortie trop longue est coupée avec `truncated: true`, sauf `read_file` qui répond `ssh_output_too_large`.
- Un délai dépassé envoie un signal puis ferme le canal, mais **la commande peut continuer de l'autre côté**.
- Un conteneur arrêté donne `guest_not_running`, verrouillé `guest_locked`.

## Workflows

Ils combinent plusieurs lectures et écritures. Une section illisible est signalée dans `unavailable` avec sa raison, et ne compte jamais comme bonne.

| Outil | Rôle |
|---|---|
| `pve_overview` | Version, nœuds, invités, stockage, HA, tâches en erreur, quorum |
| `pve_find_guest` | Cherche par vmid, nom, tag, état, nœud ou adresse IP |
| `pve_wait_task`, `pve_get_task_log_tail` | Attendre une tâche, en lire la fin du journal |
| `pve_guest_power` | Démarrer, éteindre, arrêter ou redémarrer un invité, quel que soit son type |
| `pve_snapshot_guest`, `pve_list_guest_snapshots` | Instantanés, quel que soit le type |
| `pve_provision_lxc` | Créer un conteneur : identifiant libre, modèle, réseau, clés SSH, démarrage, adresse IP |
| `pve_provision_vm_from_template` | Cloner une VM modèle, cloud-init, disque, démarrage, attente de l'agent |
| `pve_health_check` | Nœuds, quorum, stockage, services, tâches, HA, Ceph, réplication, abonnement. `overall` vaut `incomplete` si une section manque, jamais `no_findings` |
| `pve_security_audit` | Pare-feu, conteneurs privilégiés, jetons, double facteur de root, ACL trop larges, mises à jour, certificats. Ses limites figurent dans la réponse |
| `pve_backup_coverage` | Invités sans sauvegarde, tâches, âge de la dernière sauvegarde |
| `pve_capacity_report` | CPU, mémoire, disque, surallocation, projection du stockage, plus gros invités |

**Création d'un invité.** Chaque étape est rendue (`done`, `skipped`, `warning`, `failed`, `still_running`). En cas d'échec, l'erreur dit où, ce qui a été créé (`created`) et ce qui reste à faire (`remaining`). **Rien n'est jamais supprimé automatiquement**, et ces outils ne remplacent pas un invité existant. Avec 30 secondes d'attente par défaut, un clonage ou un téléchargement répondra souvent `still_running` : augmentez `wait_seconds`, en sachant que votre client MCP peut avoir son propre délai.

**Audit.** Les seuils sont des arguments, renvoyés avec le résultat. Aucun résultat ne vaut certification.

## Sécurité

**Ce qui est en place.** Un point de contrôle unique dans le client HTTP. Les chemins sont normalisés et un chemin inconnu du catalogue est refusé par défaut. Vérification TLS par défaut. Clés d'hôtes SSH vérifiées avant tout envoi d'identifiant. Masquage des secrets dans les réponses et dans le journal d'audit. Un corps de requête contenant `[REDACTED]` ou le masque `**********` de Proxmox est refusé, pour ne pas écraser le vrai secret.

### Ce qui n'est pas protégé

**SSH en root n'est pas un bac à sable.** `pve_ssh_exec`, `pve_lxc_exec` et les terminaux exécutent ce qu'on leur donne, en root sur l'hyperviseur ou dans le conteneur. Aucune politique de ce serveur ne s'applique à ce que fait une commande. `pve_ssh_exec` peut contourner toutes les portes en une ligne : `qm destroy`, `pveum`, `rm -rf`. Considérez `PROXMOX_ALLOW_SSH` avec `PROXMOX_ALLOW_WRITES` comme un accès root donné à l'agent.

**`PROXMOX_ALLOW_SSH` seul lit presque tout.** Les outils `ssh_read` n'exécutent que des commandes fixes, mais lisent en root n'importe quel fichier, sauf une courte liste : `/etc/pve/priv/*`, `/etc/shadow`, les clés privées SSH et `/proc/*/environ`. Un `.env`, un `wp-config.php` ou un `/etc/pve/storage.cfg` n'y figurent pas.

**Un jeton trop puissant reste trop puissant.** Les portes de ce serveur s'ajoutent aux droits du jeton sans les remplacer, et Proxmox reste le seul à les appliquer réellement. Un bogue ici n'est limité que par le jeton. Le serveur protège surtout contre une erreur d'agent : un jeton `PVEAuditor` protège contre tout. Donnez le minimum, avec `--privsep 1`.

**`PROXMOX_ALLOW_ELEVATED` équivaut à root sur l'hôte.** Il ouvre les hookscripts, les périphériques de l'hôte, les montages de chemins locaux, les conteneurs privilégiés, la gestion des comptes et des droits, et le remplacement de la configuration réseau.

**Hookscripts.** Un script accroché à un invité s'exécute **en root sur le nœud**, à chaque démarrage. `hookscript` demande `ALLOW_ELEVATED`, mais une **restauration** reprend la configuration de la sauvegarde, que ce serveur ne lit pas : une sauvegarde d'origine douteuse peut réintroduire un hookscript, des `args` ou un périphérique. La liste des arguments qui atteignent l'hôte n'est sûrement pas exhaustive : c'est un garde-fou, et Proxmox réserve de son côté certains d'entre eux à `root@pam`.

**Injection de prompt.** Un nom d'invité, une note, un journal, la sortie d'une commande ou le contenu d'un fichier peuvent venir d'un attaquant : ce qui tourne dans un conteneur peut écrire ce qu'il veut sur sa sortie. Le serveur marque ces sorties `untrusted: true` et le dit à l'agent, mais aucune instruction ne garantit qu'un modèle n'y réagira jamais. Avec SSH et les écritures activés, une telle injection peut aller jusqu'à root sur le nœud. Gardez la lecture seule, ou validez chaque action, dès qu'un invité exécute du contenu non fiable.

**`PROXMOX_PROTECTED_VMIDS` est un garde-fou, pas une barrière.** Il refuse une écriture quand un invité protégé est nommé : dans le chemin, en `vmid`, `newid`, `sid` HA, `target-vmid`, dans une liste `vms`, dans un identifiant de volume ou de réplication, et dans les outils LXC qui modifient. Une action groupée sans liste, et une sauvegarde `all` qui ne l'exclut pas, sont refusées aussi. Il **ne voit pas** :

- une commande SSH quelconque (`pct stop 100`) ni un terminal ;
- l'arrêt ou le redémarrage d'un **nœud**, qui arrête ses invités ;
- une sauvegarde par `pool`, un pool qu'on vide, une tâche de sauvegarde déjà planifiée ;
- la HA qui déplace ou arrête un invité par une règle, et le retrait d'un stockage qui porte ses disques ;
- les modifications du pare-feu ou du réseau qui le coupent ;
- ce qui se fait dans le système de l'invité.

**Secrets.** Le masquage repose sur le nom des champs et quelques règles par chemin : un secret dans un champ de texte libre, comme une description, n'est pas détecté, sauf les clés privées PEM, les jetons et tickets Proxmox et les identifiants dans une URL. Le jeton est dans la configuration de votre client : protégez ce fichier. `PROXMOX_ALLOW_SENSITIVE` montre des secrets à l'agent, donc à son fournisseur.

**Confirmation humaine.** Elle dépend du client, voir [Portes](#portes-et-options). Elle montre les arguments, pas leurs conséquences.

**`PROXMOX_UNBLOCK`** retire une méthode de la liste de blocage, y compris `POST /nodes/{node}/execute`, qui ferait passer des appels hors de la politique.

**Journal d'audit.** Il enregistre les écritures et les refus de ce serveur, pas ce qu'a fait une commande SSH. Il tient dans un fichier local que l'agent pourrait effacer s'il a la main sur cette machine.

### Accès réseau

En mode `--http`, le serveur écoute sur `127.0.0.1` par défaut et refuse une autre adresse sans `PROXMOX_MCP_TOKEN`. Il vérifie l'en-tête `Host` contre le rebinding DNS. Le chiffrement n'est pas fourni : placez un proxy TLS devant si le trafic quitte la machine. Ce mode n'a pas de session MCP, donc **pas de confirmation humaine** ; les terminaux SSH, eux, sont gardés dans le processus et partagés par tous ceux qui ont le jeton.

## Limites connues

- **Aucun essai sur un vrai Proxmox.** Le faux serveur vérifie les noms et les types d'après le schéma. Il ne prouve pas que Proxmox accepte chaque valeur.
- **Champs absents du schéma.** Certaines réponses y sont à peine décrites : `/nodes/{node}/replication` (`fail_count`, `error`, `last_sync`), `/cluster/tasks`, `rrddata`, `aplinfo`. Les outils composés lisent ces champs d'après ce que l'on sait de Proxmox. Si leurs noms diffèrent, un échec de réplication pourrait passer inaperçu de `pve_health_check`.
- **`pct`, gestionnaires de paquets et systèmes d'init sont simulés.** Les commandes s'exécutent dans un vrai `dash`, avec des stubs qui enregistrent leurs arguments. Les options pour Alpine sont vérifiées contre une table écrite de mémoire, pas sous BusyBox.
- **Windows seulement** pour les tests. Le SSH a aussi été testé contre un vrai OpenSSH 9.7 local, mais son `sshd` sous Windows n'applique pas le signal envoyé à une commande : la livraison du signal reste à prouver.
- **Deux tests sont ignorés sur la machine de développement** : les liens symboliques de fichiers sous `PROXMOX_LOCAL_DIR`, faute de droit pour en créer. Les répertoires liés et les jonctions sont testés.
- Les expressions régulières du schéma (`pattern`) sont en Perl : elles sont montrées dans les descriptions, pas appliquées. Une valeur mal formée reçoit l'erreur de Proxmox.
- La liste des secrets lisibles par `read_file` est une liste de refus, donc incomplète par nature.
- Les plus anciennes versions de Proxmox n'ont pas tous les points d'API : un outil répond alors `not_supported`. Le catalogue vient de la version de la documentation téléchargée (`pve_mcp_info` donne sa date).
- Pas de console interactive par websocket. `pve_ssh_session_open` en tient lieu pour un shell.
- Les rapports d'audit et de santé font des contrôles automatiques. L'absence d'un constat ne prouve pas l'absence d'un problème.

## Développement

```bash
cargo test          # tests unitaires, dont la parité des outils avec reference/
cargo build         # puis, pour les tests de bout en bout contre le binaire :
npm ci
npm test            # contre test/fake-pve.ts et test/fake-ssh.ts
npm run catalog     # régénère src/catalog/endpoints.json depuis pve.proxmox.com
```

Les tests de bout en bout (Node 20.10 ou plus récent) lancent le binaire comme le ferait un client MCP : celui de `PVEMCP_BIN`, sinon `target/release`, sinon `target/debug`. Après une régénération du catalogue, recompilez : il est intégré au binaire.

`reference/` contient ce qu'annonçait la version TypeScript d'origine (outils, prompts, ressources, instructions, noms) : `cargo test` vérifie que le binaire annonce exactement la même chose.

`node scripts/build-catalog.mjs --from apidoc.js` régénère le catalogue depuis une copie locale. Le fichier est analysé, jamais évalué, et le résultat est déterministe. Après une régénération, les tests repèrent toute méthode nouvelle sans porte attendue ni outil.

Les tests ne sortent pas de la machine et n'utilisent aucun port fixe. Ceux qui exécutent des commandes cherchent un shell POSIX (`dash`, fourni sous Windows par Git for Windows, ou `PVEMCP_TEST_SH`) et `ssh-openssh.test.ts` un `sshd` : sans eux, ils sont ignorés avec un message.

Pour essayer sur un vrai cluster sans risque : un jeton `PVEAuditor`, sans aucune option `ALLOW`. Pour vérifier une écriture : `PROXMOX_DRY_RUN=true`, ou `dry_run: true` sur l'appel.

## Remerciements

La structure et les conventions viennent d'osmcp, serveur MCP pour OPNsense : point de contrôle unique, erreurs qui guident l'agent, dry run, journal d'audit, HTTP sans session.

## Licence

MIT
