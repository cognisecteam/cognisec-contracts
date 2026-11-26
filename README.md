# Cognisec Smart Contracts

Solidity contracts for Cognisec's account and asset workflows. The contracts separate AI usage accounting from DeFi asset operations.

## What is included

- `CognisecBunkerFactory.sol` — deploys paired AI and DeFi Bunkers for an owner.
- `CognisecBunkerUpgradeable.sol` — upgradeable Bunker and factory contracts, including owner-authorized asset actions and supported-asset swaps.
- `test/CognisecBunkerV2.sol` — upgrade test implementations and local token/router fixtures.
- `docs/` — design boundaries and security assumptions.

Deployment address manifests and production deployment scripts are intentionally not part of this repository.

## Build

The source targets Solidity `^0.8.24` and imports OpenZeppelin Contracts 5.x. Run `pnpm install`, then `pnpm compile` to compile the contracts and fixtures without writing generated files. The current test folder contains Solidity fixtures; it is not a claim of complete security or behavior coverage.

## Security

These contracts can control digital assets. Review the trust model, upgrade authority, supported-asset configuration, and deployment parameters before use. This repository is not an audit, and its presence does not guarantee the safety of a deployment.

## License

The Solidity source declares MIT. The repository includes the corresponding `LICENSE` file.
