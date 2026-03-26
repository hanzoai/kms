// Unit tests for Zymbit HSM provider
// Note: These tests require actual Zymbit hardware or mocked PKCS#11 library

import { ZymbitHSM, ZymbitConfig, createZymbitHSM } from './zymbit';

// Mock pkcs11js for testing without hardware
jest.mock('pkcs11js', () => {
  return {
    PKCS11: jest.fn().mockImplementation(() => ({
      load: jest.fn(),
      C_Initialize: jest.fn(),
      C_GetSlotList: jest.fn(() => [0]),
      C_GetSlotInfo: jest.fn(() => ({
        slotDescription: 'Zymbit HSM',
        manufacturerID: 'Zymbit',
        flags: 0
      })),
      C_GetTokenInfo: jest.fn(() => ({
        label: 'Zymbit Token',
        manufacturerID: 'Zymbit',
        model: 'SCM',
        serialNumber: 'ZK-12345',
        firmwareVersion: { major: 1, minor: 2 }
      })),
      C_OpenSession: jest.fn(() => 1),
      C_Login: jest.fn(),
      C_Logout: jest.fn(),
      C_CloseSession: jest.fn(),
      C_Finalize: jest.fn(),
      C_FindObjectsInit: jest.fn(),
      C_FindObjects: jest.fn(() => [1]),
      C_FindObjectsFinal: jest.fn(),
      C_EncryptInit: jest.fn(),
      C_Encrypt: jest.fn((session, data) => Buffer.from('encrypted')),
      C_DecryptInit: jest.fn(),
      C_Decrypt: jest.fn((session, data) => Buffer.from('decrypted')),
      C_SignInit: jest.fn(),
      C_Sign: jest.fn(() => Buffer.from('signature')),
      C_VerifyInit: jest.fn(),
      C_Verify: jest.fn(),
      C_GenerateKeyPair: jest.fn(() => ({ publicKey: 1, privateKey: 2 }))
    })),
    CKF_SERIAL_SESSION: 0x00000004,
    CKF_RW_SESSION: 0x00000002,
    CKU_USER: 1,
    CKO_SECRET_KEY: 0x00000004,
    CKO_PUBLIC_KEY: 0x00000003,
    CKO_PRIVATE_KEY: 0x00000002,
    CKA_CLASS: 0x00000000,
    CKA_LABEL: 0x00000003,
    CKA_KEY_TYPE: 0x00000100,
    CKA_TOKEN: 0x00000001,
    CKA_VERIFY: 0x0000010A,
    CKA_PRIVATE: 0x00000002,
    CKA_SENSITIVE: 0x00000103,
    CKA_SIGN: 0x00000108,
    CKA_EC_PARAMS: 0x00000180,
    CKK_EC: 0x00000003,
    CKM_EC_KEY_PAIR_GEN: 0x00001040,
    CKM_AES_CBC_PAD: 0x00001085,
    CKM_ECDSA_SHA256: 0x00001042
  };
});

// Mock fs for file system checks
jest.mock('fs', () => ({
  existsSync: jest.fn((path: string) => {
    if (path.includes('libzk_pkcs11.so')) return true;
    if (path.includes('/dev/zymkey')) return true;
    return false;
  })
}));

describe('ZymbitHSM', () => {
  const validConfig: ZymbitConfig = {
    libPath: '/usr/lib/libzk_pkcs11.so',
    pin: '12345678',
    slot: 0,
    keyLabel: 'test-key',
    devicePath: '/dev/zymkey',
    enableTamperCheck: false // Disable for testing
  };

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('Constructor', () => {
    it('should create instance with valid config', () => {
      const hsm = new ZymbitHSM(validConfig);
      expect(hsm).toBeInstanceOf(ZymbitHSM);
    });

    it('should set default tamper check to true', () => {
      const config = { ...validConfig };
      delete (config as any).enableTamperCheck;
      const hsm = new ZymbitHSM(config);
      expect(hsm).toBeInstanceOf(ZymbitHSM);
    });
  });

  describe('initialize()', () => {
    it('should initialize successfully with valid config', () => {
      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.initialize()).not.toThrow();
    });

    it('should throw error if library not found', () => {
      const fs = require('fs');
      fs.existsSync.mockImplementation((path: string) => {
        if (path.includes('libzk_pkcs11.so')) return false;
        return true;
      });

      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.initialize()).toThrow('library not found');
    });

    it('should throw error if device not found', () => {
      const fs = require('fs');
      fs.existsSync.mockImplementation((path: string) => {
        if (path.includes('/dev/zymkey')) return false;
        if (path.includes('libzk_pkcs11.so')) return true;
        return false;
      });

      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.initialize()).toThrow('device not found');
    });

    it('should throw error if no slots available', () => {
      const pkcs11js = require('pkcs11js');
      pkcs11js.PKCS11.mockImplementation(() => ({
        load: jest.fn(),
        C_Initialize: jest.fn(),
        C_GetSlotList: jest.fn(() => []), // No slots
        C_Finalize: jest.fn()
      }));

      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.initialize()).toThrow('No Zymbit HSM slots found');
    });

    it('should throw error for invalid slot number', () => {
      const invalidConfig = { ...validConfig, slot: 5 };
      const hsm = new ZymbitHSM(invalidConfig);
      expect(() => hsm.initialize()).toThrow('Invalid slot');
    });
  });

  describe('finalize()', () => {
    it('should cleanup resources', () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();
      expect(() => hsm.finalize()).not.toThrow();
    });

    it('should not throw if not initialized', () => {
      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.finalize()).not.toThrow();
    });
  });

  describe('getModule()', () => {
    it('should return PKCS#11 module when initialized', () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();
      const module = hsm.getModule();
      expect(module).toBeDefined();
    });

    it('should throw error if not initialized', () => {
      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.getModule()).toThrow('not initialized');
    });
  });

  describe('checkTamperStatus()', () => {
    it('should return true for healthy device', () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();
      expect(hsm.checkTamperStatus()).toBe(true);
    });

    it('should return false if device not accessible', () => {
      const fs = require('fs');
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();

      // Simulate device disappearance
      fs.existsSync.mockReturnValue(false);
      expect(hsm.checkTamperStatus()).toBe(false);
    });

    it('should throw error if not initialized', () => {
      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.checkTamperStatus()).toThrow('not initialized');
    });
  });

  describe('getDeviceInfo()', () => {
    it('should return device information', () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();
      const info = hsm.getDeviceInfo();

      expect(info).toHaveProperty('serial');
      expect(info).toHaveProperty('firmware');
      expect(info).toHaveProperty('temperature');
      expect(info).toHaveProperty('tamperStatus');
      expect(info.tamperStatus).toBe(true);
    });

    it('should throw error if not initialized', () => {
      const hsm = new ZymbitHSM(validConfig);
      expect(() => hsm.getDeviceInfo()).toThrow('not initialized');
    });
  });

  describe('encrypt()', () => {
    it('should encrypt data successfully', async () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();

      const plaintext = Buffer.from('test data');
      const ciphertext = await hsm.encrypt(plaintext);

      expect(ciphertext).toBeInstanceOf(Buffer);
      expect(ciphertext.length).toBeGreaterThan(0);
    });

    it('should throw error if not initialized', async () => {
      const hsm = new ZymbitHSM(validConfig);
      const plaintext = Buffer.from('test data');

      await expect(hsm.encrypt(plaintext)).rejects.toThrow('not initialized');
    });
  });

  describe('decrypt()', () => {
    it('should decrypt data successfully', async () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();

      const ciphertext = Buffer.from('encrypted data');
      const plaintext = await hsm.decrypt(ciphertext);

      expect(plaintext).toBeInstanceOf(Buffer);
      expect(plaintext.length).toBeGreaterThan(0);
    });

    it('should throw error if not initialized', async () => {
      const hsm = new ZymbitHSM(validConfig);
      const ciphertext = Buffer.from('encrypted data');

      await expect(hsm.decrypt(ciphertext)).rejects.toThrow('not initialized');
    });
  });

  describe('sign()', () => {
    it('should sign data successfully', async () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();

      const data = Buffer.from('data to sign');
      const signature = await hsm.sign(data);

      expect(signature).toBeInstanceOf(Buffer);
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should throw error if not initialized', async () => {
      const hsm = new ZymbitHSM(validConfig);
      const data = Buffer.from('data to sign');

      await expect(hsm.sign(data)).rejects.toThrow('not initialized');
    });
  });

  describe('verify()', () => {
    it('should verify signature successfully', async () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();

      const data = Buffer.from('signed data');
      const signature = Buffer.from('signature');
      const isValid = await hsm.verify(data, signature);

      expect(typeof isValid).toBe('boolean');
    });

    it('should throw error if not initialized', async () => {
      const hsm = new ZymbitHSM(validConfig);
      const data = Buffer.from('signed data');
      const signature = Buffer.from('signature');

      await expect(hsm.verify(data, signature)).rejects.toThrow('not initialized');
    });
  });

  describe('generateKeyPair()', () => {
    it('should generate key pair successfully', async () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();

      const keys = await hsm.generateKeyPair();

      expect(keys).toHaveProperty('publicKey');
      expect(keys).toHaveProperty('privateKey');
    });

    it('should throw error if not initialized', async () => {
      const hsm = new ZymbitHSM(validConfig);

      await expect(hsm.generateKeyPair()).rejects.toThrow('not initialized');
    });
  });

  describe('isActive()', () => {
    it('should return true when initialized', () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();
      expect(hsm.isActive()).toBe(true);
    });

    it('should return false when not initialized', () => {
      const hsm = new ZymbitHSM(validConfig);
      expect(hsm.isActive()).toBe(false);
    });

    it('should return false after finalization', () => {
      const hsm = new ZymbitHSM(validConfig);
      hsm.initialize();
      hsm.finalize();
      expect(hsm.isActive()).toBe(false);
    });
  });

  describe('createZymbitHSM()', () => {
    beforeEach(() => {
      // Set environment variables
      process.env.HSM_LIB_PATH = '/usr/lib/libzk_pkcs11.so';
      process.env.HSM_PIN = '12345678';
      process.env.HSM_SLOT = '0';
      process.env.HSM_KEY_LABEL = 'test-key';
      process.env.ZYMBIT_DEVICE_PATH = '/dev/zymkey';
      process.env.ZYMBIT_TAMPER_CHECK = 'false';
    });

    afterEach(() => {
      // Clean up environment
      delete process.env.HSM_LIB_PATH;
      delete process.env.HSM_PIN;
      delete process.env.HSM_SLOT;
      delete process.env.HSM_KEY_LABEL;
      delete process.env.ZYMBIT_DEVICE_PATH;
      delete process.env.ZYMBIT_TAMPER_CHECK;
    });

    it('should create HSM from environment variables', () => {
      const hsm = createZymbitHSM();
      expect(hsm).toBeInstanceOf(ZymbitHSM);
    });

    it('should throw error if PIN not provided', () => {
      delete process.env.HSM_PIN;
      expect(() => createZymbitHSM()).toThrow('HSM_PIN environment variable is required');
    });

    it('should use default values for optional variables', () => {
      delete process.env.HSM_SLOT;
      delete process.env.HSM_KEY_LABEL;
      delete process.env.ZYMBIT_DEVICE_PATH;

      const hsm = createZymbitHSM();
      expect(hsm).toBeInstanceOf(ZymbitHSM);
    });
  });
});
