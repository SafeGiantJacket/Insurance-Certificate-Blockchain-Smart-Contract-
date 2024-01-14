// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CertIITech {

    struct Certificate {
        address issuer;
        address recipient;
        string data;
        bool isSigned;
        bool isValid;
        uint256 timestamp;
        uint256 invalidateAfter; 
    }

    struct PolicyInfo {
        string name;
        string phoneNumber;
        uint256 age;
        uint256 timestamp;
    }

    mapping(bytes32 => Certificate) public certificates;
    mapping(address => bytes32[]) public userCertificates; 
    mapping(address => PolicyInfo) public policyInfo;

    address public authorizedIssuer;
    address public owner;
    address[] public employees; 

    event CertificateCreated(bytes32 certificateHash, address indexed issuer, address indexed recipient);
    event CertificateSigned(bytes32 certificateHash, address indexed signer);
    event CertificateInvalidated(bytes32 certificateHash, address indexed issuer);
    event CertificateModified(bytes32 certificateHash, string newData);
    event CertificateTransferred(bytes32 certificateHash, address indexed oldOwner, address indexed newOwner, string newData);
    event PolicyPurchased(string name, address indexed ethAddress, string phoneNumber, uint256 age);
    event RequestRemoved(uint256 index);

    modifier onlyAuthorized() {
        require(msg.sender == authorizedIssuer || isEmployee(msg.sender), "Only authority or employee can call this function");
        _;
    }

    modifier onlyOwnerOrEmployee() {
        require(msg.sender == owner || isEmployee(msg.sender), "Only the owner or employee can call this function");
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    constructor() {
        authorizedIssuer = msg.sender;
        owner = msg.sender;
    }

    function isEmployee(address _address) internal view returns (bool) {
        for (uint256 i = 0; i < employees.length; i++) {
            if (employees[i] == _address) {
                return true;
            }
        }
        return false;
    }

    function addEmployee(address _employee) external onlyOwner {
        require(_employee != address(0), "Employee address is invalid");
        employees.push(_employee);
    }

    function removeEmployee(address _employee) external onlyOwner {
        for (uint256 i = 0; i < employees.length; i++) {
            if (employees[i] == _employee) {
                employees[i] = employees[employees.length - 1];
                employees.pop();
                break;
            }
        }
    }

    function generateCertificate(address _recipient, string memory _data, uint256 _invalidateAfter) external onlyAuthorized {
        bytes32 certificateHash = keccak256(abi.encodePacked(msg.sender, _recipient, _data, block.timestamp));
        require(!certificates[certificateHash].isValid, "Certificate already exists");

        Certificate memory newCertificate = Certificate({
            issuer: msg.sender,
            recipient: _recipient,
            data: _data,
            isSigned: false,
            isValid: true,
            timestamp: block.timestamp,
            invalidateAfter: _invalidateAfter
        });

        certificates[certificateHash] = newCertificate;
        userCertificates[_recipient].push(certificateHash);

        emit CertificateCreated(certificateHash, msg.sender, _recipient);
    }

    function CertificateModification(bytes32 _certificateHash, string memory _newData) external onlyAuthorized {
        require(certificates[_certificateHash].isValid, "Certificate does not exist or is invalid ");
        certificates[_certificateHash].data = _newData;

        emit CertificateModified(_certificateHash, _newData);
    }

    function signCertificate(bytes32 _certificateHash) external onlyAuthorized {
        require(certificates[_certificateHash].isValid, "Certificate does not exist or is invalid");
        certificates[_certificateHash].isSigned = true;

        emit CertificateSigned(_certificateHash, msg.sender);
    }

    function invalidateCertificate(bytes32 _certificateHash) external onlyAuthorized {
        require(certificates[_certificateHash].isValid, "Certificate does not exist or is invalid");

        certificates[_certificateHash].isValid = false;

        emit CertificateInvalidated(_certificateHash, msg.sender);
    }

    function autoInvalidateCertificate(bytes32 _certificateHash) external {
        require(certificates[_certificateHash].isValid, "Certificate does not exist or is invalid");
        require(block.timestamp >= certificates[_certificateHash].invalidateAfter, "Cannot auto-invalidate before the specified time");

        certificates[_certificateHash].isValid = false;

        emit CertificateInvalidated(_certificateHash, msg.sender);
    }

    function getCertificateDetails(bytes32 _certificateHash) external view returns (
        address issuer,
        address recipient,
        string memory data,
        bool isSigned,
        bool isValid,
        uint256 timestamp,
        uint256 invalidateAfter
    ) {
        Certificate memory certificate = certificates[_certificateHash];
        return (
            certificate.issuer,
            certificate.recipient,
            certificate.data,
            certificate.isSigned,
            certificate.isValid,
            certificate.timestamp,
            certificate.invalidateAfter
        );
    }

    function getUserCertificates(address _user) external view returns (bytes32[] memory) {
        return userCertificates[_user];
    }

    function policy(string memory _name, string memory _phoneNumber, uint256 _age) external payable {
        require(msg.value > 0, "Policy purchase requires payment of 1 Eth");

        PolicyInfo memory newPolicyInfo = PolicyInfo({
            name: _name,
            phoneNumber: _phoneNumber,
            age: _age,
            timestamp: block.timestamp
        });

        policyInfo[msg.sender] = newPolicyInfo;

        emit PolicyPurchased(_name, msg.sender, _phoneNumber, _age);
    }

    function getPolicyInfo(address _user) external view returns (
        string memory name,
        string memory phoneNumber,
        uint256 age,
        uint256 timestamp
    ) {
        PolicyInfo memory info = policyInfo[_user];
        return (
            info.name,
            info.phoneNumber,
            info.age,
            info.timestamp
        );
    }

    function withdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function hasCertificate(address _user) external view returns (bool) {
        bytes32[] memory userCertHashes = userCertificates[_user];
        return userCertHashes.length > 0;
    }

    function changeOwner(address _newOwner) external onlyOwner {
        require(_newOwner != address(0), "New owner address is invalid");
        owner = _newOwner;
    }
}
