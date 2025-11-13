Ф// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ContentRegistry {

    struct ContentInfo {
        address owner;
        uint256 timestamp;
        bytes signature; // поле для зберігання підпису
        bool exists;
    }

    mapping(bytes32 => ContentInfo) private contentRecords;

    event ContentRegistered(
        bytes32 indexed contentHash,
        address indexed owner,
        uint256 timestamp
    );

    // Функція реєстрації тепер приймає підпис
    function registerContent(bytes32 _contentHash, bytes memory _signature) public {
        require(!contentRecords[_contentHash].exists, "Content hash already registered.");

        // Верифікація підпису
        address signer = verifySignature(_contentHash, _signature);
        require(signer == msg.sender, "Invalid signature: signer does not match sender.");

        contentRecords[_contentHash] = ContentInfo({
            owner: msg.sender,
            timestamp: block.timestamp,
            signature: _signature, // збереження підпису
            exists: true
        });

        emit ContentRegistered(_contentHash, msg.sender, block.timestamp);
    }

    // Функція verifyOwnership тепер повертає і підпис
    function verifyOwnership(bytes32 _contentHash) public view returns (address owner, uint256 timestamp, bytes memory signature) {
        require(contentRecords[_contentHash].exists, "Content hash not found.");
        ContentInfo storage info = contentRecords[_contentHash];
        return (info.owner, info.timestamp, info.signature);
    }

    function isRegistered(bytes32 _contentHash) public view returns (bool) {
        return contentRecords[_contentHash].exists;
    }

    // Допоміжна функція для верифікації підпису ECDSA
    function verifySignature(bytes32 _hash, bytes memory _signature) internal pure returns (address) {
        // Ethereum підписує повідомлення, додаючи префікс. Ми повинні відтворити цей хеш.
        bytes32 messageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hash));
        
        // Розбиваємо підпис на компоненти v, r, s
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }
        
        // ecrecover повертає адресу, яка підписала повідомлення
        return ecrecover(messageHash, v, r, s);
    }
}