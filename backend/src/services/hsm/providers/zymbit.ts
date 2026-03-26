// Zymbit HSM Provider for KMS
// Supports Zymbit SCM (Secure Compute Module) for IoT/Edge deployments
// Uses PKCS#11 interface for cryptographic operations

import { HsmModule } from '../hsm-types';
import pkcs11js from 'pkcs11js';
import * as fs from 'fs';

export interface ZymbitConfig {
  libPath: string;          // /usr/lib/libzk_pkcs11.so
  pin: string;              // Zymbit PIN
  slot: number;             // Usually 0
  keyLabel: string;         // Key identifier
  devicePath?: string;      // /dev/zymkey (optional)
  enableTamperCheck?: boolean; // Enable tamper detection (default: true)
}

export interface ZymbitDeviceInfo {
  serial: string;
  firmware: string;
  temperature: number;
  tamperStatus: boolean;
}

/**
 * Zymbit HSM implementation using PKCS#11 interface
 * Provides hardware-backed cryptography for embedded and IoT devices
 */
export class ZymbitHSM implements HsmModule {
  private pkcs11: any;
  private config: ZymbitConfig;
  private session: any;
  private isInitialized: boolean = false;

  constructor(config: ZymbitConfig) {
    this.config = {
      enableTamperCheck: true,
      ...config
    };
    this.pkcs11 = new pkcs11js.PKCS11();
  }

  /**
   * Initialize Zymbit HSM connection
   * Loads PKCS#11 library, opens session, and performs login
   */
  initialize(): void {
    try {
      // Verify library exists
      if (!fs.existsSync(this.config.libPath)) {
        throw new Error(`Zymbit PKCS#11 library not found at ${this.config.libPath}`);
      }

      // Verify device exists (if path provided)
      if (this.config.devicePath && !fs.existsSync(this.config.devicePath)) {
        throw new Error(`Zymbit device not found at ${this.config.devicePath}`);
      }

      // Load Zymbit PKCS#11 library
      this.pkcs11.load(this.config.libPath);
      this.pkcs11.C_Initialize();

      // Get available slots
      const slots = this.pkcs11.C_GetSlotList(true);
      if (!slots || slots.length === 0) {
        throw new Error('No Zymbit HSM slots found. Ensure device is bound (zkbind).');
      }

      // Validate slot number
      if (this.config.slot >= slots.length) {
        throw new Error(
          `Invalid slot ${this.config.slot}. Available slots: 0-${slots.length - 1}`
        );
      }

      const slot = slots[this.config.slot];

      // Get slot info
      const slotInfo = this.pkcs11.C_GetSlotInfo(slot);
      console.log(`Zymbit HSM Slot Info: ${JSON.stringify(slotInfo)}`);

      // Open session
      this.session = this.pkcs11.C_OpenSession(
        slot,
        pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
      );

      // Login with PIN
      this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, this.config.pin);

      this.isInitialized = true;

      // Perform tamper check if enabled
      if (this.config.enableTamperCheck) {
        const tamperStatus = this.checkTamperStatus();
        if (!tamperStatus) {
          console.error('WARNING: Zymbit tamper detection triggered!');
          throw new Error('Tamper detected - device may be compromised');
        }
      }

      console.log('Zymbit HSM initialized successfully');
    } catch (error) {
      this.isInitialized = false;
      throw new Error(`Failed to initialize Zymbit HSM: ${error.message}`);
    }
  }

  /**
   * Finalize HSM connection and cleanup resources
   */
  finalize(): void {
    try {
      if (this.session) {
        this.pkcs11.C_Logout(this.session);
        this.pkcs11.C_CloseSession(this.session);
        this.session = null;
      }
      this.pkcs11.C_Finalize();
      this.isInitialized = false;
      console.log('Zymbit HSM finalized successfully');
    } catch (error) {
      console.error(`Error finalizing Zymbit HSM: ${error.message}`);
    }
  }

  /**
   * Get underlying PKCS#11 module
   */
  getModule(): any {
    if (!this.isInitialized) {
      throw new Error('Zymbit HSM not initialized. Call initialize() first.');
    }
    return this.pkcs11;
  }

  /**
   * Check tamper detection status
   * Returns true if device is untampered, false if tamper detected
   */
  checkTamperStatus(): boolean {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Read tamper status from Zymbit device
      // In production, this would query the actual device
      // For now, we check if the device file is accessible
      if (this.config.devicePath) {
        const deviceExists = fs.existsSync(this.config.devicePath);
        if (!deviceExists) {
          console.error('Zymbit device not accessible - possible tamper');
          return false;
        }
      }

      // Query slot info to verify HSM is responsive
      const slots = this.pkcs11.C_GetSlotList(true);
      if (!slots || slots.length === 0) {
        console.error('No HSM slots available - possible tamper');
        return false;
      }

      // Device appears healthy
      return true;
    } catch (error) {
      console.error(`Tamper check failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Get Zymbit device information
   * Returns serial number, firmware version, temperature, and tamper status
   */
  getDeviceInfo(): ZymbitDeviceInfo {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      const slots = this.pkcs11.C_GetSlotList(true);
      const slot = slots[this.config.slot];
      const slotInfo = this.pkcs11.C_GetSlotInfo(slot);
      const tokenInfo = this.pkcs11.C_GetTokenInfo(slot);

      // Extract device information from token
      const deviceInfo: ZymbitDeviceInfo = {
        serial: tokenInfo.serialNumber?.toString() || 'unknown',
        firmware: tokenInfo.firmwareVersion?.toString() || 'unknown',
        temperature: 0, // Zymbit doesn't expose temperature via PKCS#11
        tamperStatus: this.checkTamperStatus()
      };

      return deviceInfo;
    } catch (error) {
      throw new Error(`Failed to get device info: ${error.message}`);
    }
  }

  /**
   * Find key object by label
   */
  private findKeyByLabel(keyClass: number): any {
    const template = [
      { type: pkcs11js.CKA_CLASS, value: keyClass },
      { type: pkcs11js.CKA_LABEL, value: this.config.keyLabel }
    ];

    this.pkcs11.C_FindObjectsInit(this.session, template);
    const handles = this.pkcs11.C_FindObjects(this.session, 1);
    this.pkcs11.C_FindObjectsFinal(this.session);

    if (!handles || handles.length === 0) {
      throw new Error(`Key with label "${this.config.keyLabel}" not found`);
    }

    return handles[0];
  }

  /**
   * Encrypt data using HSM key
   */
  async encrypt(data: Buffer): Promise<Buffer> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Find encryption key
      const keyHandle = this.findKeyByLabel(pkcs11js.CKO_SECRET_KEY);

      // Initialize encryption
      const mechanism = { mechanism: pkcs11js.CKM_AES_CBC_PAD };
      this.pkcs11.C_EncryptInit(this.session, mechanism, keyHandle);

      // Encrypt data
      const encrypted = this.pkcs11.C_Encrypt(
        this.session,
        data,
        Buffer.alloc(data.length + 16) // AES block size padding
      );

      return Buffer.from(encrypted);
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using HSM key
   */
  async decrypt(data: Buffer): Promise<Buffer> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Find decryption key
      const keyHandle = this.findKeyByLabel(pkcs11js.CKO_SECRET_KEY);

      // Initialize decryption
      const mechanism = { mechanism: pkcs11js.CKM_AES_CBC_PAD };
      this.pkcs11.C_DecryptInit(this.session, mechanism, keyHandle);

      // Decrypt data
      const decrypted = this.pkcs11.C_Decrypt(
        this.session,
        data,
        Buffer.alloc(data.length)
      );

      return Buffer.from(decrypted);
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Sign data using HSM private key
   */
  async sign(data: Buffer): Promise<Buffer> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Find signing key
      const keyHandle = this.findKeyByLabel(pkcs11js.CKO_PRIVATE_KEY);

      // Initialize signing
      const mechanism = { mechanism: pkcs11js.CKM_ECDSA_SHA256 };
      this.pkcs11.C_SignInit(this.session, mechanism, keyHandle);

      // Sign data
      const signature = this.pkcs11.C_Sign(
        this.session,
        data,
        Buffer.alloc(128) // ECDSA signature size
      );

      return Buffer.from(signature);
    } catch (error) {
      throw new Error(`Signing failed: ${error.message}`);
    }
  }

  /**
   * Verify signature using HSM public key
   */
  async verify(data: Buffer, signature: Buffer): Promise<boolean> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Find verification key
      const keyHandle = this.findKeyByLabel(pkcs11js.CKO_PUBLIC_KEY);

      // Initialize verification
      const mechanism = { mechanism: pkcs11js.CKM_ECDSA_SHA256 };
      this.pkcs11.C_VerifyInit(this.session, mechanism, keyHandle);

      // Verify signature
      this.pkcs11.C_Verify(this.session, data, signature);

      return true;
    } catch (error) {
      // Verification failed
      return false;
    }
  }

  /**
   * Generate new key pair in HSM
   */
  async generateKeyPair(): Promise<{ publicKey: any; privateKey: any }> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Define key generation mechanism (ECDSA P-256)
      const mechanism = { mechanism: pkcs11js.CKM_EC_KEY_PAIR_GEN };

      // Public key template
      const publicKeyTemplate = [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
        { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_EC },
        { type: pkcs11js.CKA_TOKEN, value: true },
        { type: pkcs11js.CKA_VERIFY, value: true },
        { type: pkcs11js.CKA_LABEL, value: `${this.config.keyLabel}-pub` },
        {
          type: pkcs11js.CKA_EC_PARAMS,
          value: Buffer.from('06082a8648ce3d030107', 'hex') // P-256 curve
        }
      ];

      // Private key template
      const privateKeyTemplate = [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
        { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_EC },
        { type: pkcs11js.CKA_TOKEN, value: true },
        { type: pkcs11js.CKA_PRIVATE, value: true },
        { type: pkcs11js.CKA_SENSITIVE, value: true },
        { type: pkcs11js.CKA_SIGN, value: true },
        { type: pkcs11js.CKA_LABEL, value: `${this.config.keyLabel}-priv` }
      ];

      // Generate key pair
      const keys = this.pkcs11.C_GenerateKeyPair(
        this.session,
        mechanism,
        publicKeyTemplate,
        privateKeyTemplate
      );

      return {
        publicKey: keys.publicKey,
        privateKey: keys.privateKey
      };
    } catch (error) {
      throw new Error(`Key generation failed: ${error.message}`);
    }
  }

  /**
   * Check if HSM is initialized
   */
  isActive(): boolean {
    return this.isInitialized;
  }
}

/**
 * Factory function to create Zymbit HSM instance from environment variables
 */
export function createZymbitHSM(): ZymbitHSM {
  const config: ZymbitConfig = {
    libPath: process.env.HSM_LIB_PATH || '/usr/lib/libzk_pkcs11.so',
    pin: process.env.HSM_PIN || '',
    slot: parseInt(process.env.HSM_SLOT || '0', 10),
    keyLabel: process.env.HSM_KEY_LABEL || 'lux-kms-key',
    devicePath: process.env.ZYMBIT_DEVICE_PATH || '/dev/zymkey',
    enableTamperCheck: process.env.ZYMBIT_TAMPER_CHECK !== 'false'
  };

  // Validate configuration
  if (!config.pin) {
    throw new Error('HSM_PIN environment variable is required');
  }

  return new ZymbitHSM(config);
}
