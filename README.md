# TP_Chat_MOULIN

# td-ransomware-LBA
Q1 : Quelle est le nom de l'algorithme de chiffrement ? Est-il robuste et pourquoi ?

C'est un chiffrement symétrique, c'est robuste utilisé par les banques et les gouvernements. Il existe néanmoins des moyens de le casser, il peut etre attaqué par "Bruteforce" pour trouver la clés.Le partage de la clé est aussi un problème car il faut la partager avec le serveur de la victime pour qu'il puisse décrypter les fichiers et il faut donc que le serveur soit sécurisé et que la clé soit bien protégée pour éviter que quelqu'un d'autre ne puisse la récupérer et décrypter les fichiers de la victime sans son accord et sans qu'il le sache (ce qui est le but de ce ransomware).

Q2 : Pourquoi ne pas hacher le sel et la clef directement ? Et avec un hmac ?

Car le sel et la clé sont déjà hachés, on ne peut pas les hacher deux fois sinon on ne pourra plus les utiliser pour décrypter les fichiers car on ne pourra plus les retrouver dans le fichier de configuration du ransomware (qui contient le sel et la clé hachés).
Et il est mieux de faire les deux séparéments pour pour augmenter le temps d'execution pour rendre très longues les attaques brute force.
le hmac est utilisé pour vérifier l'intégrité des données, il est donc inutile de l'utiliser pour hacher le sel et la clé.

Q3 : Pourquoi il est préférable de vérifier qu'un fichier token.bin n'est pas déjà présent ?

Pour éviter que le ransomware ne s'execute plusieurs fois sur le même ordinateur et qu'il chiffre plusieurs fois les mêmes fichiers et ce qui aurait pour résultat de demander plusieurs fois le paiement de la rançon (ce qui est très embêtant pour la victime).


Q4 : Comment vérifier que la clef la bonne ?

On peut vérifier que la clef est bonne en la décodant en base64 et en vérifiant que la taille de la clé est bien de 32 octets (256 bits) et que la clé est bien composée de caractères alphanumériques et de caractères spéciaux.
Autrement on peut aussi vérifier que la clé est bien hachée en utilisant un hmac avec le sel et en vérifiant que le résultat est bien égal au résultat du hachage du sel et de la clé dans le fichier de configuration du ransomware.
Si la clé est bonne on peut alors décrypter les fichiers.

BONUS

Une bonne politique de sécurité implique de faire régulièrement des sauvegardes, à chaud et à
froid. Ce dernier point implique, par exemple, un disque dure USB donc hors d’atteinte. Cela
casse donc votre modèle économique. Un bon moyen est de revendre à votre victime ses propres
données : personne n’a envie de voir ses listing clients, sa compta ou les feuilles de payes être mis
en place publique. Ou pire encore.
Une solution est d’ajouter une fonction leak_files(self, files:List[str])->None dans la
classe SecretManager , devant envoyer les fichiers au CNC (ex : post_file(self, path:str,
params:dict, body:dict)->dict ).

B1 : Expliquez ce que vous faite et pourquoi

Nous allons envoyer les fichiers à notre serveur de commande et de contrôle (CNC) pour qu'il puisse les stocker et les rendre publics.Pour cela on va utiliser la fonction post_file(self, path:str, params:dict, body:dict)->dict qui permet d'envoyer un fichier au CNC parceque c'est plus simple que d'envoyer les données du fichier directement dans le corps de la requête.

B2 : Expliquez comment le casser et écrivez un script pour récupérer la clef à partir d’un fichier
chiffré et d’un fichier clair.

Pour casser le chiffrement on peut récuperer la clé à partir d'un fichier chiffré et d'un fichier clair en utilisant la fonction decrypt_file(self, path:str, params:dict, body:dict)->dict qui permet de décrypter un fichier chiffré et de le renvoyer au CNC.

B3 : quelle(s) option(s) vous est(sont) offerte(s) fiable(s) par la bibliothèque cryptographie ?
Justifiez

On peut utiliser la fonction derive_key_from_password(self, password:str, salt:bytes, iterations:int, key_length:int)->bytes qui permet de dériver une clé à partir d'un mot de passe et d'un sel et de la taille de la clé souhaitée.

B4 : Quelle ligne de commande vous faut-il avec pyinstaller pour créer le binaire ?

pyinstaller --onefile --noconsole --icon=icon.ico --name=SecretManager.exe SecretManager.py.

B5 : Où se trouve le binaire créer ?

Le binaire se trouve dans le dossier dist qui se trouve dans le dossier SecretManager.
