// AWS CloudHSM Provider Tests
// Mocked tests for AWS CloudHSM functionality

import { AWSCloudHSM, AWSCloudHSMConfig } from './aws-cloudhsm';
import * as AWS from 'aws-sdk';

// Mock AWS SDK
jest.mock('aws-sdk', () => {
  const mockDescribeClusters = jest.fn();
  const mockCreateHsm = jest.fn();
  const mockDeleteHsm = jest.fn();

  return {
    CloudHSMV2: jest.fn().mockImplementation(() => ({
      describeClusters: mockDescribeClusters,
      createHsm: mockCreateHsm,
      deleteHsm: mockDeleteHsm
    }))
  };
});

// Mock pkcs11js
jest.mock('pkcs11js', () => {
  return {
    __esModule: true,
    default: jest.fn().mockImplementation(() => ({
      load: jest.fn(),
      C_Initialize: jest.fn(),
      C_Finalize: jest.fn(),
      C_GetSlotList: jest.fn(() => [0, 1]),
      C_GetSlotInfo: jest.fn(() => ({ slotDescription: 'AWS CloudHSM Slot 0' })),
      C_GetTokenInfo: jest.fn(() => ({
        label: 'cavium',
        serialNumber: '1234567890',
        firmwareVersion: { major: 3, minor: 2 }
      })),
      C_OpenSession: jest.fn(() => 1),
      C_CloseSession: jest.fn(),
      C_Login: jest.fn(),
      C_Logout: jest.fn(),
      C_FindObjectsInit: jest.fn(),
      C_FindObjects: jest.fn(() => [1]),
      C_FindObjectsFinal: jest.fn(),
      C_EncryptInit: jest.fn(),
      C_Encrypt: jest.fn((session, data) => Buffer.concat([data, Buffer.alloc(16)])),
      C_DecryptInit: jest.fn(),
      C_Decrypt: jest.fn((session, data) => data.slice(0, data.length - 16)),
      C_SignInit: jest.fn(),
      C_Sign: jest.fn(() => Buffer.alloc(64)),
      C_VerifyInit: jest.fn(),
      C_Verify: jest.fn(),
      C_GenerateRandom: jest.fn((session, buf) => {
        for (let i = 0; i < buf.length; i++) {
          buf[i] = Math.floor(Math.random() * 256);
        }
      }),
      C_GenerateKey: jest.fn(() => 2),
      C_GenerateKeyPair: jest.fn(() => ({ publicKey: 3, privateKey: 4 })),
      C_GetSessionInfo: jest.fn(() => ({ state: 1 })),
      CKF_SERIAL_SESSION: 0x00000004,
      CKF_RW_SESSION: 0x00000002,
      CKU_USER: 1,
      CKA_CLASS: 0x00000000,
      CKA_LABEL: 0x00000003,
      CKA_KEY_TYPE: 0x00000100,
      CKA_TOKEN: 0x00000001,
      CKA_ENCRYPT: 0x00000104,
      CKA_DECRYPT: 0x00000105,
      CKA_SIGN: 0x00000108,
      CKA_VERIFY: 0x0000010A,
      CKA_PRIVATE: 0x00000002,
      CKA_SENSITIVE: 0x00000103,
      CKA_VALUE_LEN: 0x00000161,
      CKA_EC_PARAMS: 0x00000180,
      CKO_SECRET_KEY: 0x00000004,
      CKO_PUBLIC_KEY: 0x00000002,
      CKO_PRIVATE_KEY: 0x00000003,
      CKK_AES: 0x0000001F,
      CKK_EC: 0x00000003,
      CKM_AES_KEY_GEN: 0x00001080,
      CKM_AES_GCM: 0x00001087,
      CKM_EC_KEY_PAIR_GEN: 0x00001040,
      CKM_ECDSA_SHA256: 0x00001042
    }))
  };
});

// Mock fs
jest.mock('fs', () => ({
  existsSync: jest.fn(() => true)
}));

describe('AWSCloudHSM Provider', () => {
  let hsm: AWSCloudHSM;
  let config: AWSCloudHSMConfig;
  let mockCloudHSMClient: any;

  beforeEach(() => {
    jest.clearAllMocks();

    config = {
      clusterID: 'cluster-test123',
      libPath: '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
      pin: 'test-pin-1234',
      slot: 0,
      keyLabel: 'test-key',
      region: 'us-east-1'
    };

    hsm = new AWSCloudHSM(config);
    mockCloudHSMClient = (AWS.CloudHSMV2 as any).mock.results[0].value;
  });

  afterEach(() => {
    if (hsm && hsm.isActive()) {
      hsm.finalize();
    }
  });

  describe('Initialization', () => {
    it('should initialize successfully with active cluster', async () => {
      // Mock successful cluster verification
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: [
                { HsmId: 'hsm-1', State: 'ACTIVE' },
                { HsmId: 'hsm-2', State: 'ACTIVE' }
              ],
              VpcId: 'vpc-12345',
              SubnetMapping: {
                'us-east-1a': 'subnet-aaa',
                'us-east-1b': 'subnet-bbb'
              }
            }
          ]
        })
      });

      await hsm.initialize();

      expect(hsm.isActive()).toBe(true);
      expect(mockCloudHSMClient.describeClusters).toHaveBeenCalledWith({
        Filters: { clusterIds: [config.clusterID] }
      });
    });

    it('should throw error if cluster not found', async () => {
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: []
        })
      });

      await expect(hsm.initialize()).rejects.toThrow('Cluster cluster-test123 not found');
    });

    it('should throw error if cluster is not active', async () => {
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'UNINITIALIZED',
              Hsms: [{ HsmId: 'hsm-1', State: 'ACTIVE' }]
            }
          ]
        })
      });

      await expect(hsm.initialize()).rejects.toThrow('is not active');
    });

    it('should throw error if cluster has no HSMs', async () => {
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: []
            }
          ]
        })
      });

      await expect(hsm.initialize()).rejects.toThrow('has no HSMs');
    });

    it('should throw error if no active HSMs', async () => {
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: [
                { HsmId: 'hsm-1', State: 'DEGRADED' }
              ]
            }
          ]
        })
      });

      await expect(hsm.initialize()).rejects.toThrow('has no active HSMs');
    });

    it('should handle IAM permission errors', async () => {
      const error = new Error('Access denied') as any;
      error.code = 'AccessDeniedException';

      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockRejectedValue(error)
      });

      await expect(hsm.initialize()).rejects.toThrow('AWS IAM permissions insufficient');
    });
  });

  describe('Cluster Management', () => {
    beforeEach(async () => {
      // Mock successful initialization
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: [{ HsmId: 'hsm-1', State: 'ACTIVE' }],
              VpcId: 'vpc-12345',
              SubnetMapping: { 'us-east-1a': 'subnet-aaa' }
            }
          ]
        })
      });

      await hsm.initialize();
    });

    it('should get cluster info', async () => {
      const info = await hsm.getClusterInfo();

      expect(info.state).toBe('ACTIVE');
      expect(info.hsms).toBe(1);
      expect(info.vpc).toBe('vpc-12345');
      expect(info.subnets).toContain('subnet-aaa');
    });

    it('should create new HSM', async () => {
      mockCloudHSMClient.createHsm.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Hsm: { HsmId: 'hsm-new' }
        })
      });

      const hsmId = await hsm.createHSM('us-east-1b');

      expect(hsmId).toBe('hsm-new');
      expect(mockCloudHSMClient.createHsm).toHaveBeenCalledWith({
        ClusterId: config.clusterID,
        AvailabilityZone: 'us-east-1b'
      });
    });

    it('should delete HSM', async () => {
      mockCloudHSMClient.deleteHsm.mockReturnValue({
        promise: jest.fn().mockResolvedValue({})
      });

      await hsm.deleteHSM('hsm-old');

      expect(mockCloudHSMClient.deleteHsm).toHaveBeenCalledWith({
        ClusterId: config.clusterID,
        HsmId: 'hsm-old'
      });
    });
  });

  describe('Health Check', () => {
    beforeEach(async () => {
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: [
                { HsmId: 'hsm-1', State: 'ACTIVE' },
                { HsmId: 'hsm-2', State: 'ACTIVE' }
              ],
              VpcId: 'vpc-12345',
              SubnetMapping: { 'us-east-1a': 'subnet-aaa' }
            }
          ]
        })
      });

      await hsm.initialize();
    });

    it('should perform health check', async () => {
      const health = await hsm.healthCheck();

      expect(health.clusterActive).toBe(true);
      expect(health.sessionActive).toBe(true);
      expect(health.hsmCount).toBe(2);
      expect(health.lastCheckTime).toBeInstanceOf(Date);
    });

    it('should cache last health check result', async () => {
      await hsm.healthCheck();
      const cached = hsm.getLastHealthCheck();

      expect(cached).toBeDefined();
      expect(cached?.clusterActive).toBe(true);
    });
  });

  describe('Cryptographic Operations', () => {
    beforeEach(async () => {
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: [{ HsmId: 'hsm-1', State: 'ACTIVE' }],
              VpcId: 'vpc-12345'
            }
          ]
        })
      });

      await hsm.initialize();
    });

    it('should encrypt data', async () => {
      const plaintext = Buffer.from('secret data');
      const ciphertext = await hsm.encrypt(plaintext);

      expect(ciphertext).toBeInstanceOf(Buffer);
      expect(ciphertext.length).toBeGreaterThan(plaintext.length); // IV + data + tag
    });

    it('should decrypt data', async () => {
      const plaintext = Buffer.from('secret data');
      const ciphertext = await hsm.encrypt(plaintext);
      const decrypted = await hsm.decrypt(ciphertext);

      expect(decrypted).toBeInstanceOf(Buffer);
    });

    it('should sign data', async () => {
      const data = Buffer.from('message to sign');
      const signature = await hsm.sign(data);

      expect(signature).toBeInstanceOf(Buffer);
      expect(signature.length).toBe(64); // ECDSA signature
    });

    it('should verify signature', async () => {
      const data = Buffer.from('message to sign');
      const signature = await hsm.sign(data);
      const valid = await hsm.verify(data, signature);

      expect(valid).toBe(true);
    });

    it('should throw error when encrypting without initialization', async () => {
      hsm.finalize();

      await expect(hsm.encrypt(Buffer.from('test')))
        .rejects.toThrow('HSM not initialized');
    });
  });

  describe('Key Generation', () => {
    beforeEach(async () => {
      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: [{ HsmId: 'hsm-1', State: 'ACTIVE' }]
            }
          ]
        })
      });

      await hsm.initialize();
    });

    it('should generate AES-256 key', async () => {
      const keyHandle = await hsm.generateAESKey(256);

      expect(keyHandle).toBe(2); // Mocked handle
    });

    it('should generate AES-128 key', async () => {
      const keyHandle = await hsm.generateAESKey(128);

      expect(keyHandle).toBeDefined();
    });

    it('should generate EC key pair', async () => {
      const keys = await hsm.generateKeyPair();

      expect(keys.publicKey).toBe(3);
      expect(keys.privateKey).toBe(4);
    });
  });

  describe('Factory Function', () => {
    beforeEach(() => {
      process.env.AWS_CLOUDHSM_CLUSTER_ID = 'cluster-env-test';
      process.env.AWS_CLOUDHSM_PIN = 'env-pin-1234';
      process.env.AWS_REGION = 'us-west-2';
      process.env.HSM_KEY_LABEL = 'env-key';
    });

    afterEach(() => {
      delete process.env.AWS_CLOUDHSM_CLUSTER_ID;
      delete process.env.AWS_CLOUDHSM_PIN;
      delete process.env.AWS_REGION;
      delete process.env.HSM_KEY_LABEL;
    });

    it('should throw error if cluster ID missing', () => {
      delete process.env.AWS_CLOUDHSM_CLUSTER_ID;

      const { createAWSCloudHSM } = require('./aws-cloudhsm');
      expect(() => createAWSCloudHSM()).toThrow('AWS_CLOUDHSM_CLUSTER_ID');
    });

    it('should throw error if PIN missing', () => {
      delete process.env.AWS_CLOUDHSM_PIN;

      const { createAWSCloudHSM } = require('./aws-cloudhsm');
      expect(() => createAWSCloudHSM()).toThrow('AWS_CLOUDHSM_PIN');
    });
  });

  describe('Error Handling', () => {
    it('should handle PKCS#11 library not found', async () => {
      const fs = require('fs');
      fs.existsSync.mockReturnValueOnce(false);

      mockCloudHSMClient.describeClusters.mockReturnValue({
        promise: jest.fn().mockResolvedValue({
          Clusters: [
            {
              ClusterId: config.clusterID,
              State: 'ACTIVE',
              Hsms: [{ HsmId: 'hsm-1', State: 'ACTIVE' }]
            }
          ]
        })
      });

      await expect(hsm.initialize()).rejects.toThrow('library not found');
    });

    it('should finalize gracefully even if not initialized', () => {
      expect(() => hsm.finalize()).not.toThrow();
    });

    it('should throw error when calling getModule before initialize', () => {
      expect(() => hsm.getModule()).toThrow('not initialized');
    });
  });
});
