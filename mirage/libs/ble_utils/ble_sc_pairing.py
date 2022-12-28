from binascii import unhexlify
import struct
from mirage.libs.ble_utils.ble_pairing import BLEPairing
from mirage.libs import ble, io, utils
from mirage.libs.ble import PairingMethods
from mirage.libs.ble_utils.sc_crypto import SCCryptoInstance

"""
Secure Connections Pairing

Class for the secure connections pairing as master
"""


class BLESecureConnectionsPairing(BLEPairing):
    def __init__(self, pairingMethod, masterOfCOnnection):
        super().__init__(pairingMethod, masterOfCOnnection)

        self.sc_crypto = SCCryptoInstance()

        self.useOOB = False
        self.checkMitm = False
        self.ioCapabilities = False
        self.justWorks = False

        # Always Secure Connections Pairing
        self.secureConnections = True

        self.pairingResponsePkt = None

        self.localAddress = None
        self.localAddressType = None
        self.remoteAddress = None
        self.remoteAddressType = None
        self.localNonce = None
        self.remoteConfirm = None
        self.remoteIOCap = None

        self.currBitIndex = 0
        self.bitMask = 0b10000000000000000000
        self.rb = 0x00

        # For numeric comparison
        self.compareValue = ""

        self.setOwnPairingParams(secureConnections=True)

        self.setOwnKeyDistribution()

        self.pairingRequestPkt = self.getDefaultPairingRequest()

    def getCompareValue(self):

        return self.compareValue

    def generateConfirmValue(self):
        while self.pairingMethod == PairingMethods.PASSKEY_ENTRY and not self.passkey:
            utils.wait(0.2)
        if self.pairingMethod != PairingMethods.PASSKEY_ENTRY:
            self.localNonce = (
                self.localNonce if self.localNonce else self.sc_crypto.generateLocalNonce()
            )
        else:
            self.localNonce = self.sc_crypto.generateLocalNonce()

        rb = 0
        if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
            pk = int(self.passkey)
            if pk:
                rb = (pk & (2**self.currBitIndex))
                rb = rb>>self.currBitIndex
                self.currBitIndex += 1
                rb = 0b10000000 ^ rb
        self.rb = rb
        return self.sc_crypto.generateConfirmValue(rbi=bytes([rb]))


"""
Master Secure Connections Pairing

Class for the secure connections pairing as master
"""


class BLESecureConnectionsPairingMaster(BLESecureConnectionsPairing):
    def __init__(self, pairingMethod):
        super().__init__(pairingMethod, True)

    def updatePairingMethod(
        self,
        outOfBand,
        remoteAuthReq,
        remoteInputOutputCapability,
    ):
        return super().pairingMethodSelection(
            outOfBand,
            self.localAuthReq,
            remoteAuthReq,
            self.localInputOutputCapability,
            remoteInputOutputCapability,
        )

    def securityRequest(self, packet):
        return [self.pairingRequestPkt]

    def pairingResponse(
        self, packet, localAddress, localAddressType, remoteAddress, remoteAddressType
    ):
        super().pairingResponse(
            localAddress, localAddressType, remoteAddress, remoteAddressType
        )
        self.localAddress = localAddress
        self.localAddressType = localAddressType

        self.remoteAddress = remoteAddress
        self.remoteAddressType = remoteAddressType

        self.pairingResponsePkt = packet

        self.responderAuthReq = ble.AuthReqFlag(data=bytes([packet.authentication]))
        self.responderInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )

        remoteKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.responderKeyDistribution])
        )

        self.setRemoteKeydistribution(remoteKeyDistribution)

        (nwOrderPubKeyX, nwOrderPubKeyY) = self.sc_crypto.generateDHKeyPair()
        self.remoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )
        self.remoteIOCap = unhexlify(self.remoteIOCap)
        response = ble.BLEPublicKey(key_x=nwOrderPubKeyX, key_y=nwOrderPubKeyY)

        return [response]

    def publicKey(self, packet):
        self.sc_crypto.generateDHSharedSecret(packet.key_x, packet.key_y)

        responses = []
        if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
            nwOrderConfirmValue = self.generateConfirmValue()
            io.fail(f"{nwOrderConfirmValue}")
            if nwOrderConfirmValue:
                response = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
                responses.append(response)

        return responses

    def pairingConfirm(self, packet):
        while not self.sc_crypto.isSharedSecretReady():
            utils.wait(0.2)
        self.remoteConfirm = packet.confirm
        nwOrderLocalNonce = (
            self.localNonce if self.localNonce else self.sc_crypto.generateLocalNonce()
        )

        return [ble.BLEPairingRandom(random=nwOrderLocalNonce)]

    def pairingRandom(self, packet):
        responses = []
        self.remoteNonce = packet.random
        if self.sc_crypto.verifyConfirmValue(
            self.remoteNonce, self.remoteConfirm, rbi=bytes([self.rb]) if self.rb else b"\x00"
        ):
            io.info("Verify Confirm value success!")
        else:
            io.fail("Verify Confirm value failed!")
            return [ble.BLEPairingFailed()]

        if (
            self.pairingMethod == PairingMethods.PASSKEY_ENTRY
            and self.currBitIndex >= 0
        ):

            nwOrderConfirmValue = self.generateConfirmValue()
            if nwOrderConfirmValue:
                responses.append(ble.BLEPairingConfirm(confirm=nwOrderConfirmValue))
        else:
            if self.pairingMethod == PairingMethods.NUMERIC_COMPARISON:
                self.compareValue = self.sc_crypto.generateCompareValueInitiator(
                    self.remoteNonce
                )
                io.ask(f"Check Compare Value: {self.compareValue}")
            io.info("Deriving LTK")

            self.sc_crypto.deriveLTKInitiator(
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
            )
            io.info("Sending DH Key Check")
            r = b""
            if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
                r = struct.pack("<I", self.passkey)
            nwOrderDHKeyCheck = self.sc_crypto.generateDHKeyCheck(
                self.localIOCap,
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
                r,
            )
            responses.append(ble.BLEDHKeyCheck(dhkey_check=nwOrderDHKeyCheck))

        return responses

    def DHKeyCheck(self, packet):
        while not self.sc_crypto.isLTKReady():
            utils.wait(0.2)
        r = b""
        if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
            r = struct.pack("<I", self.passkey)
        if self.sc_crypto.verifyDHKeyCheck(
            self.remoteIOCap,
            self.localAddress,
            self.remoteAddress,
            self.localAddressType,
            self.remoteAddressType,
            packet.dhkey_check,
            self.remoteNonce,
            r,
        ):
            io.info("DH Key Check success!")
        else:
            io.fail("DH Key Check failed!")
            return [ble.BLEPairingFailed()]

        io.info("Try to encrypt link")
        request = ble.BLEStartEncryption(
            rand=b"\x00" * 16, ediv=0, ltk=self.sc_crypto.LTK[::-1]
        )
        return [request]

    # TODO: Add to parent
    def reestablishEncryption(self):
        request = ble.BLEStartEncryption(
            rand=b"\x00" * 16, ediv=0, ltk=self.sc_crypto.LTK[::-1]
        )
        return [request]

    def encryptionChange(self, packet):
        finished = False
        failure = False
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.info("Slave Encryption enabled !")
            if not (
                self.initiatorKeyDistribution.linkKey
                or self.initiatorKeyDistribution.signKey
                or self.initiatorKeyDistribution.idKey
            ):
                io.info("Slave pairing finished")
            finished = True
            self.setPairingFinished(True)
        else:
            io.fail("Slave Encryption failed...")
            if not self.scenarioEnabled:
                failure = True

        return (finished, failure, [])

    def longTermKeyRequest(self, packet):
        response = None
        if self.sc_crypto.isLTKReady():
            response = ble.BLELongTermKeyRequestReply(
                positive=True, ltk=self.sc_crypto.LTK[::-1]
            )
        else:
            response = ble.BLELongTermKeyRequestReply(positive=False)
        return [response]

    def identityAddressInformation(self, packet):
        self.remoteIdentityAddress = packet.address
        if not self.initiatorKeyDistribution.signKey:
            responses = self.keyDistribution(type="initiator")
            io.info("Slave pairing finished")
            self.setPairingFinished(True)
            return (True, responses)

    def identityInformation(self, packet):
        self.remoteIRK = packet.irk

    def signingInformation(self, packet):
        self.remoteCSRK = packet.csrk
        responses = self.keyDistribution(type="initiator")
        io.info("Slave pairing finished")
        self.setPairingFinished(True)
        return (True, responses)


"""
Slave Secure Connections Pairing

Class for the secure connections pairing as slave
"""


class BLESecureConnectionsPairingSlave(BLESecureConnectionsPairing):
    def __init__(self, pairingMethod):
        super().__init__(pairingMethod, False)

    def pairingRequest(
        self, packet, remoteAddress, remoteAddressType, localAddress, localAddressType
    ):
        super().pairingRequest(
            remoteAddress, remoteAddressType, localAddress, localAddressType
        )
        self.remoteAddress = remoteAddress
        self.remoteAddressType = remoteAddressType
        self.localAddress = localAddress
        self.localAddressType = localAddressType

        self.pairingRequestPkt = packet

        self.remoteAuthReq = ble.AuthReqFlag(data=bytes([packet.authentication]))
        self.remoteInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )
        remoteKeyDistribution = ble.KeyDistributionFlag(
            data=bytes([packet.initiatorKeyDistribution])
        )
        self.setRemoteKeydistribution(remoteKeyDistribution)

        self.remoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )

        self.remoteIOCap = unhexlify(self.remoteIOCap)

        self.localKeyDistribution = ble.KeyDistributionFlag(
            linkKey=self.linkKey,
            encKey=self.encKey,
            idKey=self.idKey,
            signKey=self.signKey,
        )
        oob = b"\x00"

        self.pairingResponsePkt = ble.BLEPairingResponse(
            authentication=self.localAuthReq.data[0],
            inputOutputCapability=self.localInputOutputCapability.data[0],
            initiatorKeyDistribution=self.localKeyDistribution.data[0],
            responderKeyDistribution=self.localKeyDistribution.data[0],
        )
        self.localIOCap = (
            self.localAuthReq.data + oob + self.localInputOutputCapability.data
        )

        return [self.pairingResponsePkt]

    def updatePairingMethod(
        self,
        outOfBand,
        remoteAuthReq,
        remoteInputOutputCapability,
    ):
        return super().pairingMethodSelection(
            outOfBand,
            remoteAuthReq,
            self.localAuthReq,
            remoteInputOutputCapability,
            self.localInputOutputCapability,
        )

    def publicKey(self, packet):
        (nwOrderMasterKeyX, nwORderMasterKeyY) = self.sc_crypto.generateDHKeyPair()
        response = ble.BLEPublicKey(key_x=nwOrderMasterKeyX, key_y=nwORderMasterKeyY)
        responses = []
        responses.append(response)
        io.info(f"{responses}")
        self.sc_crypto.generateDHSharedSecret(packet.key_x, packet.key_y)
        if self.pairingMethod != PairingMethods.PASSKEY_ENTRY:
            nwOrderConfirmValue = self.generateConfirmValue()
            if nwOrderConfirmValue:
                response = ble.BLEPairingConfirm(confirm=nwOrderConfirmValue)
                responses.append(response)
        io.info(f"{responses}")

        return responses

    def pairingConfirm(self, packet):
        responses = []
        self.remoteConfirm = packet.confirm
        if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
            nwOrderConfirmValue = self.generateConfirmValue()
            if nwOrderConfirmValue:
                responses.append(ble.BLEPairingConfirm(confirm=nwOrderConfirmValue))

        return responses

    def pairingRandom(self, packet):
        self.remoteNonce = packet.random
        response = None
        if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
            if self.sc_crypto.verifyConfirmValue(
                self.remoteNonce, self.remoteConfirm, rbi=bytes([self.rb])
            ):
                io.info("Verify Confirm value success!")
            else:
                io.fail("Verify Confirm value failed!")
                return [ble.BLEPairingFailed()]

        response = ble.BLEPairingRandom(random=self.localNonce)

        if self.pairingMethod == PairingMethods.NUMERIC_COMPARISON:
            self.compareValue = self.sc_crypto.generateCompareValueResponder(
                self.remoteNonce
            )
            io.success(f"Check Compare Value: {self.compareValue}")

        return [response]

    def DHKeyCheck(self, packet):
        self.sc_crypto.deriveLTKResponder(
            self.localAddress,
            self.remoteAddress,
            self.localAddressType,
            self.remoteAddressType,
            self.remoteNonce,
        )
        r = b""
        if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
            r = int(self.passkey).to_bytes(3, "little")
        response = None

        if not self.sc_crypto.verifyDHKeyCheck(
            self.remoteIOCap,
            self.localAddress,
            self.remoteAddress,
            self.localAddressType,
            self.remoteAddressType,
            packet.dhkey_check,
            self.remoteNonce,
            r,
        ):
            io.fail("DH Key Check failed!")
            response = ble.BLEPairingFailed()

        else:
            io.info("DH Key Check success!")
            io.info("Sending DH Key Check")
            nwOrderDHKeyCheck = self.sc_crypto.generateDHKeyCheck(
                self.localIOCap,
                self.localAddress,
                self.remoteAddress,
                self.localAddressType,
                self.remoteAddressType,
                self.remoteNonce,
                r,
            )
            response = ble.BLEDHKeyCheck(dhkey_check=nwOrderDHKeyCheck)

        return [response]

    def longTermKeyRequest(self, packet):
        response = None
        if self.sc_crypto.isLTKReady():
            response = ble.BLELongTermKeyRequestReply(
                positive=True, ltk=self.sc_crypto.LTK[::-1]
            )
        else:
            response = ble.BLELongTermKeyRequestReply(positive=False)
        return [response]

    def reestablishEncryption(self):
        request = ble.BLEStartEncryption(
            rand=b"\x00" * 16, ediv=0, ltk=self.sc_crypto.LTK[::-1]
        )
        return [request]

    def encryptionChange(self, packet):
        finished = False
        failed = False
        responses = []
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.success("Master Encryption enabled !")
            responses = self.keyDistribution(type="responder")
            self.setPairingFinished(True)
            finished = True
        else:
            io.fail("Master Encryption failed...")
            if not self.scenarioEnabled:
                failed = True
        return (finished, failed, responses)

    def identityAddressInformation(self, packet):
        self.remoteIdentityAddress = packet.address

        return (True, [])

    def identityInformation(self, packet):
        self.remoteIRK = packet.irk

    def signingInformation(self, packet):
        self.remoteCSRK = packet.csrk

        return (True, [])
