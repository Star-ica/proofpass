// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ProofPass
 * @dev Decentralized Identity and Credential Verification on BOT Chain
 * Stores only cryptographic commitments and revocation statuses, ensuring 
 * no raw personal data is ever exposed onchain.
 */
contract ProofPass {
    address public admin;

    struct Issuer {
        string name;
        bool isAuthorized;
        bool exists;
    }

    // Mappings
    mapping(address => Issuer) public issuers;
    
    // Maps a hash commitment (e.g., SHA256(credentialData + secretSalt)) to validity
    mapping(bytes32 => bool) public credentialCommitments;
    
    // Maps a credential commitment to its revocation status
    mapping(bytes32 => bool) public revokedCredentials;

    // Events
    event IssuerRegistered(address indexed issuerAddress, string name);
    event IssuerStatusUpdated(address indexed issuerAddress, bool isAuthorized);
    event CredentialIssued(bytes32 indexed commitment, address indexed issuer);
    event CredentialRevoked(bytes32 indexed commitment, address indexed issuer);

    modifier onlyAdmin() {
        require(msg.sender == admin, "ProofPass: Caller is not the admin");
        _;
    }

    modifier onlyAuthorizedIssuer() {
        require(issuers[msg.sender].isAuthorized, "ProofPass: Caller is not an authorized issuer");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /**
     * @dev Registers a new issuer. Only the admin can authorize issuers.
     */
    function registerIssuer(address _issuerAddress, string memory _name) external onlyAdmin {
        require(!issuers[_issuerAddress].exists, "ProofPass: Issuer already exists");
        
        issuers[_issuerAddress] = Issuer({
            name: _name,
            isAuthorized: true,
            exists: true
        });

        emit IssuerRegistered(_issuerAddress, _name);
    }

    /**
     * @dev Updates an issuer's authorization status (e.g., to suspend an issuer).
     */
    function setIssuerStatus(address _issuerAddress, bool _isAuthorized) external onlyAdmin {
        require(issuers[_issuerAddress].exists, "ProofPass: Issuer does not exist");
        issuers[_issuerAddress].isAuthorized = _isAuthorized;
        
        emit IssuerStatusUpdated(_issuerAddress, _isAuthorized);
    }

    /**
     * @dev Issues a new credential by storing its cryptographic commitment onchain.
     */
    function issueCredential(bytes32 _commitment) external onlyAuthorizedIssuer {
        require(!credentialCommitments[_commitment], "ProofPass: Credential commitment already exists");
        
        credentialCommitments[_commitment] = true;
        
        emit CredentialIssued(_commitment, msg.sender);
    }

    /**
     * @dev Revokes a previously issued credential.
     */
    function revokeCredential(bytes32 _commitment) external onlyAuthorizedIssuer {
        require(credentialCommitments[_commitment], "ProofPass: Credential commitment does not exist");
        require(!revokedCredentials[_commitment], "ProofPass: Credential is already revoked");
        
        revokedCredentials[_commitment] = true;
        
        emit CredentialRevoked(_commitment, msg.sender);
    }

    /**
     * @dev Verifies if a credential commitment is valid and not revoked.
     * Used by Verifiers in conjunction with offchain ZK proofs.
     */
    function isCredentialValid(bytes32 _commitment) external view returns (bool) {
        return credentialCommitments[_commitment] && !revokedCredentials[_commitment];
    }
}