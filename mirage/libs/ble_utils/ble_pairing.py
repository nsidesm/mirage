import math
from mirage.libs.ble import PairingMethods
from mirage.libs import io
from mirage.libs.ble_utils.constants import *
from mirage.libs.ble_utils.dissectors import AuthReqFlag, InputOutputCapability
from mirage.libs.ble_utils.packets import (
    BLEIdentityAddressInformation,
    BLEIdentityInformation,
    BLESigningInformation,
)
from mirage.libs.ble_utils.sc_crypto import CryptoUtils
import random
from mirage.libs.ble_utils.dissectors import KeyDistributionFlag
from mirage.libs.ble_utils.packets import BLEPairingRequest


class BLEPairing:
    def __init__(self, pairingMethod, masterOfConnection):
        self.pairingFinished = False
        self.pairingMethod = pairingMethod
        # TODO: How to handle bonding
        self.bonding = False
        self.masterOfConnection = masterOfConnection
        # Set to None so that pairing fails if no proper pairing method is set
        self.keyboard = None
        self.yesno = None
        self.display = None
        self.ct2 = None
        self.mitm = None
        self.keyPress = None

        self.localAuthReq = None
        self.localInputOutputCapability = None
        self.localIOCap = None

        self.localKeyDistribution = None

        self.initiatorKeyDistribution = None
        self.responderKeyDistribution = None

        # For Passkey Entry
        self.passkey = None

        # Results
        self.localIRK = None
        self.localCSRK = None
        self.remoteIRK = None
        self.remoteCSRK = None
        self.remoteIdentityAddress = None

    def setPairingFinished(self, pairingFinished):
        self.pairingFinished = pairingFinished

    def isPairingFinished(self):
        return self.pairingFinished

    def setPassKey(self, passkey):
        self.passkey = passkey
        return []

    def setOwnPairingParams(self, secureConnections):
        if not self.pairingMethod:
            io.fail("No Pairing Method selected, do not know what to do")
            return
        elif self.pairingMethod == PairingMethods.JUST_WORKS:
            self.keyboard = False
            self.yesno = False
            self.display = False
            self.ct2 = False
            self.mitm = False
            self.keyPress = False
        elif (
            self.pairingMethod == PairingMethods.PASSKEY_ENTRY
            and not self.masterOfConnection
        ):
            self.keyboard = True
            self.yesno = False
            self.display = False
            self.ct2 = False
            self.mitm = True
            self.keyPress = False
        elif (
            self.pairingMethod == PairingMethods.NUMERIC_COMPARISON
            and secureConnections
        ) or (
            self.pairingMethod == PairingMethods.PASSKEY_ENTRY
            and self.masterOfConnection
        ):
            self.keyboard = True
            self.yesno = True
            self.display = True
            self.ct2 = False
            self.mitm = True
            self.keyPress = False
        else:
            io.fail(
                f"Some strange Pairing Method is set, cannot handle this {self.pairingMethod} - {secureConnections}"
            )
            return

        self.localInputOutputCapability = InputOutputCapability(
            keyboard=self.keyboard, display=self.display, yesno=self.yesno
        )

        self.localAuthReq = AuthReqFlag(
            ct2=self.ct2,
            mitm=self.mitm,
            bonding=self.bonding,
            secureConnections=secureConnections,
            keypress=self.keyPress,
        )

    def createPasskey(self, length=6):
        digits = [i for i in range(0, 10)]
        pin = ""

        for i in range(length):
            index = math.floor(random.random() * 10)
            pin += str(digits[index])

        return pin

    def setOwnKeyDistribution(
        self, linkKey=False, encKey=False, idKey=False, signKey=False
    ):
        self.linkKey = linkKey
        self.encKey = encKey
        self.idKey = idKey
        self.signKey = signKey

    def setRemoteKeydistribution(self, remoteKeyDistribution):
        if self.masterOfConnection:
            self.initiatorKeyDistribution = self.localKeyDistribution
            self.responderKeyDistribution = remoteKeyDistribution
        else:
            self.initiatorKeyDistribution = remoteKeyDistribution
            self.responderKeyDistribution = self.localKeyDistribution

    def pairingMethodSelection(
        self,
        outOfBand,
        initiatorAuthReq,
        responderAuthReq,
        initiatorInputOutputCapability,
        responderInputOutputCapability,
    ):
        secureConnections = (
            responderAuthReq.secureConnections and initiatorAuthReq.secureConnections
        )
        if secureConnections:
            io.info("Using LE secure connections")
        else:
            io.info("Using LE legacy pairing")

        useOOB = outOfBand
        ioCapabilities = responderAuthReq.mitm or initiatorAuthReq.mitm
        justWorks = not responderAuthReq.mitm and not initiatorAuthReq.mitm

        io.chart(
            ["Out Of Bond", "IO Capabilities", "Just Works"],
            [
                [
                    "yes" if useOOB else "no",
                    "yes" if ioCapabilities else "no",
                    "yes" if justWorks else "no",
                ]
            ],
        )

        if ioCapabilities:
            initiator = "NoInputNoOutput"
            responder = "NoInputNoOutput"
            if initiatorInputOutputCapability.data[0] == 0x00:
                initiator = "DisplayOnly"
            elif initiatorInputOutputCapability.data[0] == 0x01:
                initiator = "DisplayYesNo"
            elif initiatorInputOutputCapability.data[0] == 0x02:
                initiator = "KeyboardOnly"
            elif initiatorInputOutputCapability.data[0] == 0x03:
                initiator = "NoInputNoOutput"
            elif initiatorInputOutputCapability.data[0] == 0x04:
                initiator = "KeyboardDisplay"

            if responderInputOutputCapability.data[0] == 0x00:
                responder = "DisplayOnly"
            elif responderInputOutputCapability.data[0] == 0x01:
                responder = "DisplayYesNo"
            elif responderInputOutputCapability.data[0] == 0x02:
                responder = "KeyboardOnly"
            elif responderInputOutputCapability.data[0] == 0x03:
                responder = "NoInputNoOutput"
            elif responderInputOutputCapability.data[0] == 0x04:
                responder = "KeyboardDisplay"

            self.pairingMethod = PairingMethods.getPairingMethod(
                secureConnections=secureConnections,
                initiatorInputOutputCapability=initiator,
                responderInputOutputCapability=responder,
            )

            if self.pairingMethod == PairingMethods.PASSKEY_ENTRY:
                io.info("Pairing with PasskeyEntry")
            elif self.pairingMethod == PairingMethods.NUMERIC_COMPARISON:
                io.info("Pairing with NumericComparison")
            else:
                io.info("Pairing with JustWorks")
        elif useOOB:
            io.fail("Pairing with OOB")
        else:
            io.info("Pairing with JustWorks")

        return (secureConnections, self.pairingMethod)

    def getDefaultPairingRequest(self):

        self.localKeyDistribution = KeyDistributionFlag(
            linkKey=self.linkKey,
            encKey=self.encKey,
            idKey=self.idKey,
            signKey=self.signKey,
        )
        oob = b"\x00"
        self.localIOCap = (
            self.localAuthReq.data + oob + self.localInputOutputCapability.data
        )

        self.pairingRequestPkt = BLEPairingRequest(
            authentication=self.localAuthReq.data[0],
            inputOutputCapability=self.localInputOutputCapability.data[0],
            initiatorKeyDistribution=self.localKeyDistribution.data[0],
            responderKeyDistribution=self.localKeyDistribution.data[0],
        )
        return self.pairingRequestPkt

    def securityRequest(self, pkt):
        return []

    def pairingResponse(
        self,
        pkt,
        localAddress=None,
        localAddressType=None,
        remoteAddress=None,
        remoteAddressType=None,
    ):
        self.remoteAddress = remoteAddress
        self.remoteAddressType = remoteAddressType
        self.localAddress = localAddress
        self.localAddressType = localAddressType
        return []

    def pairingRequest(
        self,
        pkt,
        remoteAddress=None,
        remoteAddressType=None,
        localAddress=None,
        localAddressType=None,
    ):
        self.remoteAddress = remoteAddress
        self.remoteAddressType = remoteAddressType
        self.localAddress = localAddress
        self.localAddressType = localAddressType
        return []

    def pairingConfirm(self, pkt):
        return []

    def pairingRandom(self, pkt):
        return []

    def publicKey(self, pkt):
        return []

    def DHKeyCheck(self, pkt):
        return []

    def encryptionChange(self, pkt):
        return (False, False, [])

    def pairingFailed(self, pkt):
        self.failure = True
        io.fail("Pairing Failed received : " + pkt.toString())
        self.pairingFailedMsg(pkt)

    def pairingFailedMsg(self, pkt):
        if pkt.reason == SM_ERR_PASSKEY_ENTRY_FAILED:
            io.fail("Reason : Passkey Entry Failed")
        elif pkt.reason == SM_ERR_OOB_NOT_AVAILABLE:
            io.fail("Reason : Out of Band not available")
        elif pkt.reason == SM_ERR_AUTH_REQUIREMENTS:
            io.fail("Reason : Authentication requirements")
        elif pkt.reason == SM_ERR_CONFIRM_VALUE_FAILED:
            io.fail("Reason : Confirm Value failed")
        elif pkt.reason == SM_ERR_PAIRING_NOT_SUPPORTED:
            io.fail("Reason : Pairing not supported")
        elif pkt.reason == SM_ERR_OOB_NOT_AVAILABLE:
            io.fail("Reason : Out of Band not available")
        elif pkt.reason == SM_ERR_ENCRYPTION_KEY_SIZE:
            io.fail("Reason : Encryption key size")
        elif pkt.reason == SM_ERR_COMMAND_NOT_SUPPORTED:
            io.fail("Reason : Command not supported")
        elif pkt.reason == SM_ERR_UNSPECIFIED_REASON:
            io.fail("Reason : Unspecified reason")
        elif pkt.reason == SM_ERR_REPEATED_ATTEMPTS:
            io.fail("Reason : Repeated Attempts")
        elif pkt.reason == SM_ERR_INVALID_PARAMETERS:
            io.fail("Reason : Invalid Parameters")
        elif pkt.reason == SM_ERR_DHKEY_CHECK_FAILED:
            io.fail("Reason : DHKey Check failed")
        elif pkt.reason == SM_ERR_NUMERIC_COMPARISON_FAILED:
            io.fail("Reason : Numeric Comparison failed")
        elif pkt.reason == SM_ERR_BREDR_PAIRING_IN_PROGRESS:
            io.fail("Reason : BR/EDR Pairing in progress")
        elif pkt.reason == SM_ERR_CROSS_TRANSPORT_KEY:
            io.fail("Reason : Cross-transport Key Derivation/Generation not allowed")
        else:
            io.fail("Reason : unknown")

    def keyDistribution(self, type="initiator"):

        io.info("Key Distribution!")
        if type == "initiator":
            keyDistribution = self.initiatorKeyDistribution
        else:
            keyDistribution = self.responderKeyDistribution

        response = []
        if keyDistribution.idKey:
            self.localIRK = CryptoUtils.generateRandom()
            response.append(
                BLEIdentityInformation(
                    irk=CryptoUtils.reverseOrder(self.localIRK.hex())
                )
            )
            response.append(
                BLEIdentityAddressInformation(
                    address=self.localAddress,
                    type=self.localAddressType,
                )
            )

        if keyDistribution.signKey:
            self.localCSRK = CryptoUtils.generateRandom()
            response.append(
                BLESigningInformation(
                    csrk=CryptoUtils.reverseOrder(self.localCSRK.hex())
                )
            )

        return response

    def longTermKeyRequest(self, pkt):
        return []

    def encryptionInformation(self, pkt):
        return []

    def masterIdentification(self, pkt):
        return []

    def identityAddressInformation(self, pkt):
        return []

    def identityInformation(self, pkt):
        return []

    def signingInformation(self, pkt):
        return []
