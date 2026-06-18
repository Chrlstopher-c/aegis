/*
 * Règles de test Aegis. Convention de métadonnées lue par aegis-detection :
 *   severity : Info|Low|Medium|High|Critical
 *   category : Execution|Persistence|PrivilegeEscalation|DefenseEvasion|
 *              CredentialAccess|CommandAndControl|Impact|Signature
 *   mitre    : techniques séparées par des virgules, ex "T1059.004,T1486"
 *   description : texte court affiché dans le verdict
 */

rule eicar_test_file {
    meta:
        severity = "High"
        category = "Signature"
        mitre = "T1204"
        description = "Fichier de test antivirus standard EICAR"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule suspicious_reverse_shell_oneliner {
    meta:
        severity = "Critical"
        category = "CommandAndControl"
        mitre = "T1059.004"
        description = "One-liner de reverse shell (redirection shell vers socket)"
    strings:
        $bash_dev_tcp = "/dev/tcp/" ascii
        $sh_i = "sh -i" ascii
        $bash_i = "bash -i" ascii
    condition:
        $bash_dev_tcp and ($sh_i or $bash_i)
}
