from binascii import unhexlify
from os import urandom
from mirage.libs.ble_utils.ble_pairing import BLEPairing
from mirage.libs.ble_utils.crypto import BLECrypto
from mirage.libs.ble_utils.dissectors import (
    AuthReqFlag,
    InputOutputCapability,
    KeyDistributionFlag,
)
from mirage.libs.ble_utils.packets import *
from mirage.libs.bt_utils.assigned_numbers import PairingMethods
from mirage.libs import io, utils

"""
Legacy Pairing

Class for the secure connections pairing as master, currently supports JUST_WORKS and PASSKEY_ENTRY
"""


class BLELegacyPairing(BLEPairing):
    def __init__(self, pairingMethod, masterOfCOnnection, pairingData=None):
        super().__init__(pairingMethod, masterOfCOnnection)

        # Always Secure Connections Pairing
        self.secureConnections = False

        self.setOwnPairingParams(secureConnections=False)

        self.setOwnKeyDistribution()

        # Security Manager related
        if pairingData:
            self.independent = False
            self.pairingData = pairingData
        else:
            self.independent = True
            self.pairingData = {
                "pReq": None,
                "pRes": None,
                "mRand": None,
                "mConfirm": None,
                "sRand": None,
                "sConfirm": None,
                "forgedsRand": None,
                "temporaryKey": None,
                "pin": None,
                "shortTermKey": None,
                "ediv": None,
                "rand": None,
            }

        # Default Pairing Request
        self.pairingRequestPkt = self.getDefaultPairingRequest()

        self.initiatorAddress = None
        self.initiatorAddressType = None
        self.responderAddress = None
        self.responderAddressType = None

        # Legacy pairing Specific Results
        self.ltk = None
        self.ediv = None
        self.rand = None

    def getDefaultPairingRequest(self):
        pairingRequestPkt = None
        if self.independent:
            pairingRequestPkt = super().getDefaultPairingRequest()
            self.pairingData["pReq"] = pairingRequestPkt.payload[::-1]
        else:
            self.pairingData["pReq"] = None
        return pairingRequestPkt

    def pinToTemporaryKey(self, pin):
        hexn = hex(pin)[2:]
        tk = bytes.fromhex((32 - len(hexn)) * "0" + hexn)
        return tk

    def keyGeneration(self, size=16):
        return urandom(size)

    def getPinIndependentMode(self):
        while self.pairingMethod == PairingMethods.PASSKEY_ENTRY and not self.passkey:
            utils.wait(0.2)
        io.info(f"Passkey! {self.passkey}")
        return self.passkey


class BLELegacyPairingMaster(BLELegacyPairing):
    def __init__(self, pairingMethod, pairingData=None):
        super().__init__(pairingMethod, True, pairingData)

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

    def securityRequest(self, pkt):
        io.info("Master: {}".format(packet))
        io.info("Master: {}".format(self.pairingRequestPkt))

        while not self.pairingRequestPkt:
            utils.wait(0.2)

        response = self.pairingRequestPkt
        return [response]

    def pairingResponse(
        self, packet, localAddress, localAddressType, remoteAddress, remoteAddressType
    ):

        io.info("Master: {}".format(packet))

        self.pairingData["pRes"] = packet.payload[::-1]

        self.localAddressType = b"\x00" if localAddressType == 0 else b"\x01"
        self.localAddress = localAddress
        self.remoteAddressType = b"\x00" if remoteAddressType == 0 else b"\x01"
        self.remoteAddress = remoteAddress

        remoteKeyDistribution = KeyDistributionFlag(
            data=bytes([packet.initiatorKeyDistribution])
        )

        self.setRemoteKeydistribution(remoteKeyDistribution)

        if self.independent:
            self.pairingData["mRand"] = BLECrypto.generateRandom()

            if self.pairingMethod == PairingMethods.JUST_WORKS:
                self.pairingData["pin"] = 0
            else:
                self.pairingData["pin"] = self.getPinIndependentMode()

            self.pairingData["temporaryKey"] = self.pinToTemporaryKey(
                self.pairingData["pin"]
            )
            self.pairingData["mConfirm"] = BLECrypto.c1(
                self.pairingData["temporaryKey"],
                self.pairingData["mRand"][::-1],
                self.pairingData["pReq"],
                self.pairingData["pRes"],
                self.localAddressType,
                self.localAddress,
                self.remoteAddressType,
                self.remoteAddress,
            )

        while not self.pairingData["mConfirm"]:
            utils.wait(0.2)
        response = BLEPairingConfirm(confirm=self.pairingData["mConfirm"][::-1])
        return [response]

    def pairingConfirm(self, packet):
        io.info("Master: {}".format(packet))
        self.pairingData["sConfirm"] = packet.confirm[::-1]
        while not self.pairingData["mRand"]:
            utils.wait(0.2)
        response = BLEPairingRandom(random=self.pairingData["mRand"])
        return [response]

    def pairingRandom(self, packet):
        io.info("Master: {}".format(packet))

        self.pairingData["sRand"] = packet.random[::-1]

        if self.independent:
            sConfirm = BLECrypto.c1(
                self.pairingData["temporaryKey"],
                self.pairingData["sRand"],
                self.pairingData["pReq"],
                self.pairingData["pRes"],
                self.localAddressType,
                self.localAddress,
                self.remoteAddressType,
                self.remoteAddress,
            )
            if self.pairingData["sConfirm"] == sConfirm:
                io.info("Confirm Value correct!")
                self.pairingData["shortTermKey"] = BLECrypto.s1(
                    self.pairingData["temporaryKey"],
                    self.pairingData["mRand"][::-1],
                    self.pairingData["sRand"],
                )[::-1]
                self.pairingData["rand"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"
                self.pairingData["ediv"] = 0
            else:
                io.fail("Verify Confirm value failed!")
                return [BLEPairingFailed()]

        io.info("Stuck!")
        while not (
            self.pairingData["shortTermKey"]
            and self.pairingData["rand"]
            and (self.pairingData["ediv"] or self.pairingData["ediv"] == 0)
        ):
            utils.wait(0.2)
        io.info("Try to encrypt link")
        response = BLELongTermKeyRequest(
            rand=self.pairingData["rand"],
            ediv=self.pairingData["ediv"],
            ltk=self.pairingData["shortTermKey"],
        )
        return [response]

    def encryptionChange(self, packet):
        io.info("Master: {}".format(packet))
        finished = False
        failure = False
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.info("Encryption enabled !")
            if not (
                self.responderKeyDistribution.linkKey
                or self.responderKeyDistribution.signKey
                or self.responderKeyDistribution.idKey
            ):
                io.info("Slave pairing finished")
                finished = True
                self.pairingFinished = True
        else:
            io.fail("Slave Encryption failed...")
            if not self.scenarioEnabled:
                failure = True

        return (finished, failure, [])

    def encryptionInformation(self, packet):
        io.info("Master: {}".format(packet))
        self.ltk = packet.ltk
        return []

    def masterIdentification(self, packet):
        io.info("Master: {}".format(packet))
        self.rand = packet.rand
        self.ediv = packet.ediv
        return []

    def identityAddressInformation(self, packet):
        self.remoteIdentityAddress = packet.address
        if not self.responderKeyDistribution.signKey:
            responses = self.keyDistribution(type="initiator")
            io.info("Slave pairing finished")
            return (True, responses)

    def identityInformation(self, packet):
        io.info("Master: {}".format(packet))
        self.remoteIRK = packet.irk

    def signingInformation(self, packet):
        self.remoteCSRK = packet.csrk
        responses = self.keyDistribution(type="initiator")
        io.info("Slave pairing finished")
        return (True, responses)


class BLELegacyPairingSlave(BLELegacyPairing):
    def __init__(self, pairingMethod, pairingData=None):
        super().__init__(pairingMethod, False, pairingData)
        io.info("BLELegacyPairingSlave initialized.")

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

    def pairingRequest(
        self, packet, remoteAddress, remoteAddressType, localAddress, localAddressType
    ):
        self.localAddressType = b"\x00" if localAddressType == 0 else b"\x01"
        self.localAddress = localAddress
        self.remoteAddressType = b"\x00" if remoteAddressType == 0 else b"\x01"
        self.remoteAddress = remoteAddress

        io.info("Slave: {}".format(packet))
        self.pairingRequestPkt = packet
        self.pairingData["pReq"] = packet.payload[::-1]

        self.remoteAuthReq = AuthReqFlag(data=bytes([packet.authentication]))
        self.remoteInputOutputCapability = InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )
        remoteKeyDistribution = KeyDistributionFlag(
            data=bytes([packet.initiatorKeyDistribution])
        )

        self.setRemoteKeydistribution(remoteKeyDistribution)

        self.remoteIOCap = (
            format(packet.authentication, "02x")
            + ("01" if packet.outOfBand else "00")
            + format(packet.inputOutputCapability, "02x")
        )

        self.remoteIOCap = unhexlify(self.remoteIOCap)

        self.localKeyDistribution = KeyDistributionFlag(
            linkKey=self.linkKey,
            encKey=self.encKey,
            idKey=self.idKey,
            signKey=self.signKey,
        )
        oob = b"\x00"

        self.pairingResponsePkt = BLEPairingResponse(
            authentication=self.localAuthReq.data[0],
            inputOutputCapability=self.localInputOutputCapability.data[0],
            initiatorKeyDistribution=self.localKeyDistribution.data[0],
            responderKeyDistribution=self.localKeyDistribution.data[0],
        )
        self.localIOCap = (
            self.localAuthReq.data + oob + self.localInputOutputCapability.data
        )
        io.info("Slave: {}".format(self.pairingResponsePkt))

        if self.independent:
            self.pairingData["pRes"] = self.pairingResponsePkt.payload[::-1]

        return [self.pairingResponsePkt]

    def pairingConfirm(self, packet):
        io.info("Slave: {}".format(packet))

        self.pairingData["mConfirm"] = packet.confirm[::-1]

        if self.independent:
            self.pairingData["sRand"] = BLECrypto.generateRandom()

            if self.pairingMethod == PairingMethods.JUST_WORKS:
                self.pairingData["pin"] = 0
            else:
                self.pairingData["pin"] = int(
                    io.enterPinCode("Enter the 6 digit PIN code: ")
                )

            self.pairingData["temporaryKey"] = self.pinToTemporaryKey(
                self.pairingData["pin"]
            )
            self.pairingData["sConfirm"] = BLECrypto.c1(
                self.pairingData["temporaryKey"],
                self.pairingData["sRand"][::-1],
                self.pairingData["pReq"],
                self.pairingData["pRes"],
                self.remoteAddressType,
                self.remoteAddress,
                self.localAddressType,
                self.localAddress,
            )
            io.info(
                "Generating Temporary Key : " + self.pairingData["temporaryKey"].hex()
            )

        while not self.pairingData["sConfirm"]:
            utils.wait(0.2)
        response = BLEPairingConfirm(confirm=self.pairingData["sConfirm"])
        return [response]

    def pairingRandom(self, packet):
        io.info("Slave: {}".format(packet))
        self.pairingData["mRand"] = packet.random[::-1]

        if self.independent:
            mConfirm = BLECrypto.c1(
                self.pairingData["temporaryKey"],
                self.pairingData["mRand"][::-1],
                self.pairingData["pReq"],
                self.pairingData["pRes"],
                self.remoteAddressType,
                self.remoteAddress,
                self.localAddressType,
                self.localAddress,
            )

            if self.pairingData["mConfirm"] == mConfirm:
                io.info("Confirm Value correct !")
                self.pairingData["shortTermKey"] = BLECrypto.s1(
                    self.temporaryKey, self.mRand, self.sRand
                )[::-1]
                self.pairingData["rand"] = b"\x00\x00\x00\x00\x00\x00\x00\x00"
                self.pairingData["ediv"] = 0
                io.info("Generating Short Term Key (STK): " + self.stk.hex())
            else:
                io.fail("Verify Confirm value failed!")
                return [BLEPairingFailed()]

        else:
            while not (
                self.pairingData["mRand"]
                and self.pairingData["pReq"]
                and self.pairingData["pRes"]
                and self.pairingData["mConfirm"]
            ):
                utils.wait(0.2)

            m = utils.loadModule("ble_crack")
            m["MASTER_RAND"] = self.pairingData["mRand"].hex()
            m["PAIRING_REQUEST"] = self.pairingData["pReq"].hex()
            m["PAIRING_RESPONSE"] = self.pairingData["pRes"].hex()
            m["INITIATOR_ADDRESS_TYPE"] = (
                "public" if self.localAddressType == b"\x00" else "random"
            )
            m["INITIATOR_ADDRESS"] = self.localAddress
            m["RESPONDER_ADDRESS_TYPE"] = (
                "public" if self.remoteAddressType == b"\x00" else "random"
            )
            m["RESPONDER_ADDRESS"] = self.remoteAddress
            m["MASTER_CONFIRM"] = self.pairingData["mConfirm"].hex()
            output = m.run()

            if output["success"]:
                self.pairingData["pin"] = int(output["output"]["PIN"])
                self.pairingData["temporaryKey"] = bytes.fromhex(
                    output["output"]["TEMPORARY_KEY"]
                )
                io.fail(
                    f'PIN: {self.pairingData["pin"]}, TEMP_KEY: {self.pairingData["temporaryKey"]}'
                )
            else:
                io.fail("Something went wrong, cannot crack PIN")
                return []

        while not self.pairingData["sRand"]:
            utils.wait(0.2)

        response = BLEPairingRandom(random=self.pairingData["sRand"])
        return [response]

    def longTermKeyRequest(self, packet):
        io.info("Slave: {}".format(packet))
        responses = []
        if packet.ediv == 0 and packet.rand == b"\x00" * 8:
            self.pairingData["shortTermKey"] = BLECrypto.s1(
                self.pairingData["temporaryKey"],
                self.pairingData["mRand"],
                self.pairingData["sRand"],
            )[::-1]
            io.info(
                "Derivating Short Term Key : " + self.pairingData["shortTermKey"].hex()
            )
            io.info("Redirecting to slave ...")
            responses.append(
                BLELongTermKeyRequestReply(positive=True, ltk=self.shortTermKey)
            )
        else:
            io.info("Something went wrong")
        return [responses]

    def encryptionChange(self, packet):
        io.info("Slave: {}".format(packet))
        finished = False
        failed = False
        responses = []
        if packet.status == 0x00 and packet.enabled == 0x01:
            io.success("Encryption enabled !")
            responses = self.keyDistribution(type="responder")
        else:
            io.fail("Master Encryption failed...")
            if not self.scenarioEnabled:
                failure = True
        return (finished, failed, responses)

    def encryptionInformation(self, packet):
        io.info("Slave: {}".format(packet))
        self.ltk = packet.ltk
        return []

    def masterIdentification(self, packet):
        io.info("Slave: {}".format(packet))
        self.rand = packet.rand
        self.ediv = packet.ediv
        return []

    def identityAddressInformation(self, packet):
        self.remoteIdentityAddress = packet.address
        if not self.responderKeyDistribution.signKey:
            responses = self.keyDistribution(type="initiator")
            io.info("Slave pairing finished")
            return (True, responses)
        return (False, [])

    def identityInformation(self, packet):
        self.remoteIRK = packet.irk

    def signingInformation(self, packet):
        self.remoteCSRK = packet.csrk
        responses = self.keyDistribution(type="initiator")
        io.info("Slave pairing finished")
        return (True, responses)
