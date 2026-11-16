#ifndef LORAWAN_AUDITOR_H
#define LORAWAN_AUDITOR_H

#include "lorawan_types.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Execute the 10-rule sovereign LoRaWAN security posture audit */
void lorawan_audit_policy(const gateway_policy_t *policy, audit_report_t *report);

/* Severity helper */
const char *audit_severity_to_str(audit_severity_t sev);

#ifdef __cplusplus
}
#endif

#endif /* LORAWAN_AUDITOR_H */
