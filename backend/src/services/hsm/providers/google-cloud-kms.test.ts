// Google Cloud KMS Provider Tests
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { GoogleCloudKMS, GoogleCloudKMSConfig, createGoogleCloudKMS } from './google-cloud-kms';

// Mock Google Cloud KMS client
vi.mock('@google-cloud/kms', () => {
  const mockClient = {
    cryptoKeyPath: vi.fn((projectId, locationId, keyRingId, cryptoKeyId) => {
      return `projects/${projectId}/locations/${locationId}/keyRings/${keyRingId}/cryptoKeys/${cryptoKeyId}`;
    }),
    locationPath: vi.fn((projectId, locationId) => {
      return `projects/${projectId}/locations/${locationId}`;
    }),
    keyRingPath: vi.fn((projectId, locationId, keyRingId) => {
      return `projects/${projectId}/locations/${locationId}/keyRings/${keyRingId}`;
    }),
    getCryptoKey: vi.fn().mockResolvedValue([
      {
        name: 'test-key',
        purpose: 'ENCRYPT_DECRYPT',
        versionTemplate: {
          protectionLevel: 'HSM',
          algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION'
        },
        primary: {
          name: 'test-key/cryptoKeyVersions/1',
          state: 'ENABLED'
        },
        createTime: { seconds: '1234567890' }
      }
    ]),
    getKeyRing: vi.fn().mockResolvedValue([
      {
        name: 'test-keyring'
      }
    ]),
    createKeyRing: vi.fn().mockResolvedValue([
      {
        name: 'test-keyring'
      }
    ]),
    createCryptoKey: vi.fn().mockResolvedValue([
      {
        name: 'test-key'
      }
    ]),
    encrypt: vi.fn().mockImplementation(({ plaintext }) => {
      // Mock encryption: reverse the bytes for testing
      const reversed = Buffer.from(plaintext).reverse();
      return Promise.resolve([{ ciphertext: reversed }]);
    }),
    decrypt: vi.fn().mockImplementation(({ ciphertext }) => {
      // Mock decryption: reverse the bytes back
      const reversed = Buffer.from(ciphertext).reverse();
      return Promise.resolve([{ plaintext: reversed }]);
    }),
    createCryptoKeyVersion: vi.fn().mockResolvedValue([
      {
        name: 'test-key/cryptoKeyVersions/2',
        state: 'ENABLED'
      }
    ]),
    updateCryptoKeyPrimaryVersion: vi.fn().mockResolvedValue([{}]),
    listLocations: vi.fn().mockResolvedValue([
      [
        { locationId: 'global' },
        { locationId: 'us-east1' },
        { locationId: 'us-west1' },
        { locationId: 'europe-west1' }
      ]
    ]),
    listCryptoKeyVersions: vi.fn().mockResolvedValue([
      [
        {
          name: 'test-key/cryptoKeyVersions/1',
          state: 'ENABLED',
          protectionLevel: 'HSM',
          algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
          createTime: { seconds: '1234567890' }
        },
        {
          name: 'test-key/cryptoKeyVersions/2',
          state: 'DISABLED',
          protectionLevel: 'HSM',
          algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION',
          createTime: { seconds: '1234567900' }
        }
      ]
    ]),
    updateCryptoKeyVersion: vi.fn().mockResolvedValue([{}]),
    close: vi.fn().mockResolvedValue(undefined)
  };

  return {
    KeyManagementServiceClient: vi.fn(() => mockClient),
    protos: {
      google: {
        cloud: {
          kms: {
            v1: {}
          }
        }
      }
    }
  };
});

describe('GoogleCloudKMS', () => {
  let kms: GoogleCloudKMS;
  let config: GoogleCloudKMSConfig;

  beforeEach(() => {
    config = {
      projectId: 'test-project',
      locationId: 'global',
      keyRingId: 'test-keyring',
      cryptoKeyId: 'test-key',
      protectionLevel: 'HSM'
    };
  });

  afterEach(async () => {
    if (kms && kms.isActive()) {
      await kms.finalize();
    }
    vi.clearAllMocks();
  });

  describe('initialization', () => {
    it('should initialize successfully with valid config', async () => {
      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      expect(kms.isActive()).toBe(true);
    });

    it('should create key ring if it does not exist', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      // Mock key ring not found
      (mockClient.getKeyRing as any).mockRejectedValueOnce({ code: 5 });

      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      expect(mockClient.createKeyRing).toHaveBeenCalled();
    });

    it('should create crypto key if it does not exist', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      // Mock crypto key not found
      (mockClient.getCryptoKey as any).mockRejectedValueOnce({ code: 5 });

      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      expect(mockClient.createCryptoKey).toHaveBeenCalled();
    });

    it('should throw error if key is not enabled', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      // Mock disabled key
      (mockClient.getCryptoKey as any).mockResolvedValueOnce([
        {
          versionTemplate: { protectionLevel: 'HSM' },
          primary: { state: 'DISABLED' }
        }
      ]);

      kms = new GoogleCloudKMS(config);

      await expect(kms.initialize()).rejects.toThrow('Key primary version is not enabled');
    });

    it('should initialize with service account credentials', async () => {
      const configWithCreds = {
        ...config,
        credentialsPath: '/path/to/service-account.json'
      };

      kms = new GoogleCloudKMS(configWithCreds);
      await kms.initialize();

      expect(kms.isActive()).toBe(true);
    });

    it('should default to HSM protection level', async () => {
      const configNoProtection = {
        ...config
      };
      delete (configNoProtection as any).protectionLevel;

      kms = new GoogleCloudKMS(configNoProtection);
      await kms.initialize();

      expect(kms.isActive()).toBe(true);
    });
  });

  describe('encryption and decryption', () => {
    beforeEach(async () => {
      kms = new GoogleCloudKMS(config);
      await kms.initialize();
    });

    it('should encrypt data successfully', async () => {
      const plaintext = Buffer.from('test data to encrypt');
      const ciphertext = await kms.encrypt(plaintext);

      expect(ciphertext).toBeInstanceOf(Buffer);
      expect(ciphertext).not.toEqual(plaintext);
    });

    it('should decrypt data successfully', async () => {
      const plaintext = Buffer.from('test data to encrypt and decrypt');
      const ciphertext = await kms.encrypt(plaintext);
      const decrypted = await kms.decrypt(ciphertext);

      expect(decrypted).toBeInstanceOf(Buffer);
      expect(decrypted.toString()).toBe(plaintext.toString());
    });

    it('should handle empty plaintext', async () => {
      const plaintext = Buffer.from('');
      const ciphertext = await kms.encrypt(plaintext);
      const decrypted = await kms.decrypt(ciphertext);

      expect(decrypted.toString()).toBe('');
    });

    it('should handle large data', async () => {
      const plaintext = Buffer.alloc(10 * 1024 * 1024); // 10 MB
      plaintext.fill('x');

      const ciphertext = await kms.encrypt(plaintext);
      const decrypted = await kms.decrypt(ciphertext);

      expect(decrypted.length).toBe(plaintext.length);
    });

    it('should throw error when encrypting without initialization', async () => {
      const uninitializedKms = new GoogleCloudKMS(config);
      const plaintext = Buffer.from('test data');

      await expect(uninitializedKms.encrypt(plaintext)).rejects.toThrow(
        'KMS not initialized'
      );
    });

    it('should throw error when decrypting without initialization', async () => {
      const uninitializedKms = new GoogleCloudKMS(config);
      const ciphertext = Buffer.from('encrypted data');

      await expect(uninitializedKms.decrypt(ciphertext)).rejects.toThrow(
        'KMS not initialized'
      );
    });
  });

  describe('key management', () => {
    beforeEach(async () => {
      kms = new GoogleCloudKMS(config);
      await kms.initialize();
    });

    it('should rotate key successfully', async () => {
      await kms.rotateKey();

      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      expect(mockClient.createCryptoKeyVersion).toHaveBeenCalled();
      expect(mockClient.updateCryptoKeyPrimaryVersion).toHaveBeenCalled();
    });

    it('should get key information', async () => {
      const keyInfo = await kms.getKeyInfo();

      expect(keyInfo).toBeDefined();
      expect(keyInfo.purpose).toBe('ENCRYPT_DECRYPT');
      expect(keyInfo.protectionLevel).toBe('HSM');
      expect(keyInfo.primaryState).toBe('ENABLED');
    });

    it('should list key versions', async () => {
      const versions = await kms.listKeyVersions();

      expect(versions).toBeInstanceOf(Array);
      expect(versions.length).toBe(2);
      expect(versions[0].state).toBe('ENABLED');
      expect(versions[1].state).toBe('DISABLED');
    });

    it('should disable key version', async () => {
      await kms.disableKeyVersion('1');

      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      expect(mockClient.updateCryptoKeyVersion).toHaveBeenCalledWith(
        expect.objectContaining({
          cryptoKeyVersion: expect.objectContaining({
            state: 'DISABLED'
          })
        })
      );
    });

    it('should enable key version', async () => {
      await kms.enableKeyVersion('2');

      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      expect(mockClient.updateCryptoKeyVersion).toHaveBeenCalledWith(
        expect.objectContaining({
          cryptoKeyVersion: expect.objectContaining({
            state: 'ENABLED'
          })
        })
      );
    });
  });

  describe('location management', () => {
    beforeEach(async () => {
      kms = new GoogleCloudKMS(config);
      await kms.initialize();
    });

    it('should list available locations', async () => {
      const locations = await kms.getKeyLocations();

      expect(locations).toBeInstanceOf(Array);
      expect(locations).toContain('global');
      expect(locations).toContain('us-east1');
      expect(locations).toContain('europe-west1');
    });
  });

  describe('health check', () => {
    beforeEach(async () => {
      kms = new GoogleCloudKMS(config);
      await kms.initialize();
    });

    it('should pass health check when operational', async () => {
      const health = await kms.healthCheck();

      expect(health.healthy).toBe(true);
      expect(health.details.encryptionTest).toBe('PASSED');
      expect(health.details.keyInfo).toBeDefined();
    });

    it('should fail health check on encryption error', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      // Mock encryption failure
      (mockClient.encrypt as any).mockRejectedValueOnce(new Error('Encryption failed'));

      const health = await kms.healthCheck();

      expect(health.healthy).toBe(false);
      expect(health.details.error).toBeDefined();
    });
  });

  describe('finalization', () => {
    it('should finalize successfully', async () => {
      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      expect(kms.isActive()).toBe(true);

      await kms.finalize();

      expect(kms.isActive()).toBe(false);
    });

    it('should handle finalization errors gracefully', async () => {
      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      // Mock close error
      (mockClient.close as any).mockRejectedValueOnce(new Error('Close failed'));

      await expect(kms.finalize()).resolves.not.toThrow();
      expect(kms.isActive()).toBe(false);
    });
  });

  describe('factory function', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it('should create instance from environment variables', () => {
      process.env.GOOGLE_CLOUD_PROJECT_ID = 'test-project';
      process.env.GOOGLE_CLOUD_LOCATION = 'us-east1';
      process.env.GOOGLE_CLOUD_KEY_RING = 'test-keyring';
      process.env.GOOGLE_CLOUD_CRYPTO_KEY = 'test-key';
      process.env.GOOGLE_CLOUD_PROTECTION_LEVEL = 'HSM';

      const instance = createGoogleCloudKMS();

      expect(instance).toBeInstanceOf(GoogleCloudKMS);
    });

    it('should use default values when optional env vars are missing', () => {
      process.env.GOOGLE_CLOUD_PROJECT_ID = 'test-project';

      const instance = createGoogleCloudKMS();

      expect(instance).toBeInstanceOf(GoogleCloudKMS);
    });

    it('should throw error when required env vars are missing', () => {
      delete process.env.GOOGLE_CLOUD_PROJECT_ID;

      expect(() => createGoogleCloudKMS()).toThrow(
        'GOOGLE_CLOUD_PROJECT_ID environment variable is required'
      );
    });

    it('should handle auto-rotate configuration', () => {
      process.env.GOOGLE_CLOUD_PROJECT_ID = 'test-project';
      process.env.GOOGLE_CLOUD_AUTO_ROTATE = 'true';
      process.env.GOOGLE_CLOUD_ROTATION_PERIOD = '2592000s'; // 30 days

      const instance = createGoogleCloudKMS();

      expect(instance).toBeInstanceOf(GoogleCloudKMS);
    });
  });

  describe('error handling', () => {
    it('should handle network errors during initialization', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      // Mock network error
      (mockClient.getCryptoKey as any).mockRejectedValueOnce(
        new Error('Network error')
      );

      kms = new GoogleCloudKMS(config);

      await expect(kms.initialize()).rejects.toThrow(
        'Failed to initialize Google Cloud KMS'
      );
    });

    it('should handle API errors during encryption', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      // Mock encryption error
      (mockClient.encrypt as any).mockRejectedValueOnce(
        new Error('Permission denied')
      );

      const plaintext = Buffer.from('test data');

      await expect(kms.encrypt(plaintext)).rejects.toThrow(
        'Google Cloud KMS encryption failed'
      );
    });

    it('should handle missing ciphertext in encryption response', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      // Mock empty response
      (mockClient.encrypt as any).mockResolvedValueOnce([{}]);

      const plaintext = Buffer.from('test data');

      await expect(kms.encrypt(plaintext)).rejects.toThrow(
        'Encryption returned no ciphertext'
      );
    });

    it('should handle missing plaintext in decryption response', async () => {
      const { KeyManagementServiceClient } = await import('@google-cloud/kms');
      const mockClient = new KeyManagementServiceClient();

      kms = new GoogleCloudKMS(config);
      await kms.initialize();

      // Mock empty response
      (mockClient.decrypt as any).mockResolvedValueOnce([{}]);

      const ciphertext = Buffer.from('encrypted data');

      await expect(kms.decrypt(ciphertext)).rejects.toThrow(
        'Decryption returned no plaintext'
      );
    });
  });
});
