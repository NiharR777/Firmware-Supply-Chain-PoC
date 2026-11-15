
rule Synthetic_Ransomware_Signature
{
    meta:
        indicator_type = "ransomware_signature"
        severity = "critical"
        confidence_percent = 90
        description = "Synthetic ransomware signature marker detected."

    strings:
        $marker = "SYNTHETIC_RANSOMWARE_SIGNATURE_MARKER" ascii

    condition:
        $marker
}

rule Synthetic_Ransom_Note
{
    meta:
        indicator_type = "ransom_note_artifact"
        severity = "high"
        confidence_percent = 85
        description = "Synthetic ransom note marker detected."

    strings:
        $marker = "SYNTHETIC_RANSOM_NOTE_MARKER" ascii

    condition:
        $marker
}

rule Synthetic_Encryption_Routine
{
    meta:
        indicator_type = "encryption_routine_indicator"
        severity = "high"
        confidence_percent = 80
        description = "Synthetic encryption routine marker detected."

    strings:
        $marker = "SYNTHETIC_ENCRYPTION_ROUTINE_MARKER" ascii

    condition:
        $marker
}

rule Synthetic_Recovery_Inhibition
{
    meta:
        indicator_type = "recovery_inhibition_indicator"
        severity = "high"
        confidence_percent = 85
        description = "Synthetic recovery inhibition marker detected."

    strings:
        $marker = "SYNTHETIC_RECOVERY_INHIBITION_MARKER" ascii

    condition:
        $marker
}

rule Synthetic_Suspicious_Persistence
{
    meta:
        indicator_type = "suspicious_persistence"
        severity = "medium"
        confidence_percent = 75
        description = "Synthetic persistence marker detected."

    strings:
        $marker = "SYNTHETIC_PERSISTENCE_MARKER" ascii

    condition:
        $marker
}
