# Contract Security Assumptions

The contracts separate AI usage accounting from DeFi asset actions. This separation does not make either account risk-free.

## Trust boundaries

- The account owner controls owner-authorized withdrawals and DeFi actions.
- The AI billing controller can reserve, settle, or release AI usage according to the contract rules.
- The configured treasury receives settled AI usage.
- The upgrade authority and beacon configuration are critical security controls in upgradeable deployments.
- Supported asset and router configuration determine which swap paths are allowed.

## Review before use

Review signatures, nonce and deadline handling, reentrancy behavior, asset token assumptions, upgrade authorization, and initialization. Confirm chain-specific addresses and deployment parameters independently. Do not treat compilation or local fixtures as an audit.

## Operational safety

Never place private keys, signed transactions, production deployment manifests, or owner credentials in this repository. Production deployment and upgrade procedures require separate approval and review.
