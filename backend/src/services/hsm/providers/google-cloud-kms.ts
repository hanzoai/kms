// Google Cloud KMS HSM Provider for Lux KMS
// Supports Google Cloud Key Management Service for enterprise cloud deployments
// Uses REST API and gRPC for cryptographic operations

import { HsmModule } from '../hsm-types';
import { KeyManagementServiceClient } from '@google-cloud/kms';
import { protos } from '@google-cloud/kms';

export interface GoogleCloudKMSConfig {
  projectId: string;
  locationId: string;        // e.g., 'global', 'us-east1', 'europe-west1'
  keyRingId: string;         // Key ring name
  cryptoKeyId: string;       // Crypto key ID
  credentialsPath?: string;  // Path to service account JSON
  protectionLevel?: 'SOFTWARE' | 'HSM';  // HSM for hardware-backed keys
  keyVersion?: string;       // Specific key version (optional)
  autoRotate?: boolean;      // Enable automatic key rotation (default: false)
  rotationPeriod?: string;   // Rotation period in seconds (e.g., '7776000s' for 90 days)
}

/**
 * Google Cloud KMS HSM implementation
 * Provides hardware-backed cryptography using Google Cloud infrastructure
 *
 * Features:
 * - Global key management
 * - Hardware-backed HSM keys
 * - Automatic key rotation
 * - Multi-region replication
 * - IAM-based access control
 */
export class GoogleCloudKMS implements HsmModule {
  private client: KeyManagementServiceClient;
  private config: GoogleCloudKMSConfig;
  private keyName: string;
  private isInitialized: boolean = false;

  constructor(config: GoogleCloudKMSConfig) {
    this.config = {
      protectionLevel: 'HSM',  // Default to HSM for hardware-backed keys
      autoRotate: false,
      ...config
    };

    // Initialize Google Cloud KMS client
    const clientConfig = config.credentialsPath
      ? { keyFilename: config.credentialsPath }
      : {};  // Uses Application Default Credentials (ADC)

    this.client = new KeyManagementServiceClient(clientConfig);

    // Build full key resource name
    this.keyName = this.client.cryptoKeyPath(
      config.projectId,
      config.locationId,
      config.keyRingId,
      config.cryptoKeyId
    );
  }

  /**
   * Initialize Google Cloud KMS connection
   * Creates key ring and crypto key if they don't exist
   * Verifies key is HSM-backed
   */
  async initialize(): Promise<void> {
    try {
      // Create key ring if doesn't exist
      await this.ensureKeyRing();

      // Create crypto key if doesn't exist
      await this.ensureCryptoKey();

      // Verify key configuration
      const [key] = await this.client.getCryptoKey({ name: this.keyName });

      // Verify protection level (HSM vs SOFTWARE)
      if (key.versionTemplate?.protectionLevel !== this.config.protectionLevel) {
        console.warn(
          `Warning: Key protection level is ${key.versionTemplate?.protectionLevel}, ` +
          `expected ${this.config.protectionLevel}`
        );
      }

      // Verify key is enabled
      if (key.primary?.state !== 'ENABLED') {
        throw new Error(
          `Key primary version is not enabled. State: ${key.primary?.state}`
        );
      }

      this.isInitialized = true;
      console.log(
        `Google Cloud KMS initialized successfully. Key: ${this.keyName}, ` +
        `Protection: ${key.versionTemplate?.protectionLevel}`
      );
    } catch (error: any) {
      this.isInitialized = false;
      throw new Error(`Failed to initialize Google Cloud KMS: ${error.message}`);
    }
  }

  /**
   * Finalize KMS connection and cleanup resources
   */
  async finalize(): Promise<void> {
    try {
      // Close gRPC connection
      await this.client.close();
      this.isInitialized = false;
      console.log('Google Cloud KMS finalized successfully');
    } catch (error: any) {
      console.error(`Error finalizing Google Cloud KMS: ${error.message}`);
    }
  }

  /**
   * Get underlying Google Cloud KMS client
   */
  getModule(): KeyManagementServiceClient {
    if (!this.isInitialized) {
      throw new Error('Google Cloud KMS not initialized. Call initialize() first.');
    }
    return this.client;
  }

  /**
   * Encrypt data using Google Cloud KMS
   *
   * @param plaintext - Data to encrypt
   * @returns Encrypted ciphertext
   */
  async encrypt(plaintext: Buffer): Promise<Buffer> {
    try {
      if (!this.isInitialized) {
        throw new Error('KMS not initialized');
      }

      const [result] = await this.client.encrypt({
        name: this.keyName,
        plaintext: plaintext
      });

      if (!result.ciphertext) {
        throw new Error('Encryption returned no ciphertext');
      }

      return Buffer.from(result.ciphertext as Uint8Array);
    } catch (error: any) {
      throw new Error(`Google Cloud KMS encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using Google Cloud KMS
   *
   * @param ciphertext - Data to decrypt
   * @returns Decrypted plaintext
   */
  async decrypt(ciphertext: Buffer): Promise<Buffer> {
    try {
      if (!this.isInitialized) {
        throw new Error('KMS not initialized');
      }

      const [result] = await this.client.decrypt({
        name: this.keyName,
        ciphertext: ciphertext
      });

      if (!result.plaintext) {
        throw new Error('Decryption returned no plaintext');
      }

      return Buffer.from(result.plaintext as Uint8Array);
    } catch (error: any) {
      throw new Error(`Google Cloud KMS decryption failed: ${error.message}`);
    }
  }

  /**
   * Create key ring if it doesn't exist
   */
  private async ensureKeyRing(): Promise<void> {
    const parent = this.client.locationPath(
      this.config.projectId,
      this.config.locationId
    );

    try {
      // Try to get key ring first
      const keyRingName = this.client.keyRingPath(
        this.config.projectId,
        this.config.locationId,
        this.config.keyRingId
      );

      await this.client.getKeyRing({ name: keyRingName });
      // Key ring exists
    } catch (err: any) {
      if (err.code === 5) {  // NOT_FOUND
        // Create key ring
        await this.client.createKeyRing({
          parent,
          keyRingId: this.config.keyRingId
        });
        console.log(`Created key ring: ${this.config.keyRingId}`);
      } else {
        throw err;
      }
    }
  }

  /**
   * Create crypto key if it doesn't exist
   */
  private async ensureCryptoKey(): Promise<void> {
    const parent = this.client.keyRingPath(
      this.config.projectId,
      this.config.locationId,
      this.config.keyRingId
    );

    try {
      // Try to get crypto key first
      await this.client.getCryptoKey({ name: this.keyName });
      // Crypto key exists
    } catch (err: any) {
      if (err.code === 5) {  // NOT_FOUND
        // Create crypto key
        const cryptoKey: protos.google.cloud.kms.v1.ICryptoKey = {
          purpose: 'ENCRYPT_DECRYPT',
          versionTemplate: {
            protectionLevel: this.config.protectionLevel,
            algorithm: 'GOOGLE_SYMMETRIC_ENCRYPTION'
          }
        };

        // Add rotation schedule if auto-rotate enabled
        if (this.config.autoRotate && this.config.rotationPeriod) {
          cryptoKey.rotationPeriod = {
            seconds: this.config.rotationPeriod
          };
          cryptoKey.nextRotationTime = {
            seconds: (Date.now() / 1000).toString()
          };
        }

        await this.client.createCryptoKey({
          parent,
          cryptoKeyId: this.config.cryptoKeyId,
          cryptoKey
        });
        console.log(`Created crypto key: ${this.config.cryptoKeyId}`);
      } else {
        throw err;
      }
    }
  }

  /**
   * Rotate key to new version
   * Creates a new primary key version
   */
  async rotateKey(): Promise<void> {
    try {
      if (!this.isInitialized) {
        throw new Error('KMS not initialized');
      }

      // Create new key version
      const [keyVersion] = await this.client.createCryptoKeyVersion({
        parent: this.keyName,
        cryptoKeyVersion: {
          state: 'ENABLED'
        }
      });

      // Set as primary version
      await this.client.updateCryptoKeyPrimaryVersion({
        name: this.keyName,
        cryptoKeyVersionId: keyVersion.name?.split('/').pop() || ''
      });

      console.log(`Key rotated successfully. New version: ${keyVersion.name}`);
    } catch (error: any) {
      throw new Error(`Key rotation failed: ${error.message}`);
    }
  }

  /**
   * Get list of available GCP locations for KMS
   */
  async getKeyLocations(): Promise<string[]> {
    try {
      const [locations] = await this.client.listLocations({
        name: `projects/${this.config.projectId}`
      });
      return locations.map(l => l.locationId || '').filter(id => id);
    } catch (error: any) {
      throw new Error(`Failed to list locations: ${error.message}`);
    }
  }

  /**
   * Get key information including versions and metadata
   */
  async getKeyInfo(): Promise<any> {
    try {
      if (!this.isInitialized) {
        throw new Error('KMS not initialized');
      }

      const [key] = await this.client.getCryptoKey({ name: this.keyName });

      return {
        name: key.name,
        purpose: key.purpose,
        protectionLevel: key.versionTemplate?.protectionLevel,
        algorithm: key.versionTemplate?.algorithm,
        primaryVersion: key.primary?.name,
        primaryState: key.primary?.state,
        createTime: key.createTime,
        rotationPeriod: key.rotationPeriod,
        nextRotationTime: key.nextRotationTime
      };
    } catch (error: any) {
      throw new Error(`Failed to get key info: ${error.message}`);
    }
  }

  /**
   * List all key versions
   */
  async listKeyVersions(): Promise<any[]> {
    try {
      if (!this.isInitialized) {
        throw new Error('KMS not initialized');
      }

      const [versions] = await this.client.listCryptoKeyVersions({
        parent: this.keyName
      });

      return versions.map(v => ({
        name: v.name,
        state: v.state,
        protectionLevel: v.protectionLevel,
        algorithm: v.algorithm,
        createTime: v.createTime,
        destroyTime: v.destroyTime,
        destroyEventTime: v.destroyEventTime
      }));
    } catch (error: any) {
      throw new Error(`Failed to list key versions: ${error.message}`);
    }
  }

  /**
   * Disable a specific key version
   */
  async disableKeyVersion(versionId: string): Promise<void> {
    try {
      if (!this.isInitialized) {
        throw new Error('KMS not initialized');
      }

      const versionName = `${this.keyName}/cryptoKeyVersions/${versionId}`;

      await this.client.updateCryptoKeyVersion({
        cryptoKeyVersion: {
          name: versionName,
          state: 'DISABLED'
        },
        updateMask: {
          paths: ['state']
        }
      });

      console.log(`Key version ${versionId} disabled`);
    } catch (error: any) {
      throw new Error(`Failed to disable key version: ${error.message}`);
    }
  }

  /**
   * Enable a specific key version
   */
  async enableKeyVersion(versionId: string): Promise<void> {
    try {
      if (!this.isInitialized) {
        throw new Error('KMS not initialized');
      }

      const versionName = `${this.keyName}/cryptoKeyVersions/${versionId}`;

      await this.client.updateCryptoKeyVersion({
        cryptoKeyVersion: {
          name: versionName,
          state: 'ENABLED'
        },
        updateMask: {
          paths: ['state']
        }
      });

      console.log(`Key version ${versionId} enabled`);
    } catch (error: any) {
      throw new Error(`Failed to enable key version: ${error.message}`);
    }
  }

  /**
   * Check if KMS is initialized and operational
   */
  isActive(): boolean {
    return this.isInitialized;
  }

  /**
   * Test KMS connectivity and permissions
   */
  async healthCheck(): Promise<{
    healthy: boolean;
    details: any;
  }> {
    try {
      // Try to get key info
      const keyInfo = await this.getKeyInfo();

      // Try a test encryption/decryption cycle
      const testData = Buffer.from('health-check-test-data');
      const encrypted = await this.encrypt(testData);
      const decrypted = await this.decrypt(encrypted);

      const healthy = decrypted.equals(testData);

      return {
        healthy,
        details: {
          keyInfo,
          encryptionTest: healthy ? 'PASSED' : 'FAILED',
          timestamp: new Date().toISOString()
        }
      };
    } catch (error: any) {
      return {
        healthy: false,
        details: {
          error: error.message,
          timestamp: new Date().toISOString()
        }
      };
    }
  }
}

/**
 * Factory function to create Google Cloud KMS instance from environment variables
 *
 * Environment variables:
 * - GOOGLE_CLOUD_PROJECT_ID: GCP project ID
 * - GOOGLE_CLOUD_LOCATION: GCP region (e.g., 'global', 'us-east1')
 * - GOOGLE_CLOUD_KEY_RING: Key ring name
 * - GOOGLE_CLOUD_CRYPTO_KEY: Crypto key name
 * - GOOGLE_APPLICATION_CREDENTIALS: Path to service account JSON (optional, uses ADC if not set)
 * - GOOGLE_CLOUD_PROTECTION_LEVEL: 'HSM' or 'SOFTWARE' (default: 'HSM')
 * - GOOGLE_CLOUD_AUTO_ROTATE: 'true' to enable automatic rotation (default: 'false')
 * - GOOGLE_CLOUD_ROTATION_PERIOD: Rotation period in seconds (default: '7776000' = 90 days)
 */
export function createGoogleCloudKMS(): GoogleCloudKMS {
  const config: GoogleCloudKMSConfig = {
    projectId: process.env.GOOGLE_CLOUD_PROJECT_ID || '',
    locationId: process.env.GOOGLE_CLOUD_LOCATION || 'global',
    keyRingId: process.env.GOOGLE_CLOUD_KEY_RING || 'lux-kms-keyring',
    cryptoKeyId: process.env.GOOGLE_CLOUD_CRYPTO_KEY || 'lux-kms-key',
    credentialsPath: process.env.GOOGLE_APPLICATION_CREDENTIALS,
    protectionLevel: (process.env.GOOGLE_CLOUD_PROTECTION_LEVEL as 'HSM' | 'SOFTWARE') || 'HSM',
    autoRotate: process.env.GOOGLE_CLOUD_AUTO_ROTATE === 'true',
    rotationPeriod: process.env.GOOGLE_CLOUD_ROTATION_PERIOD || '7776000s'  // 90 days
  };

  // Validate required configuration
  if (!config.projectId) {
    throw new Error('GOOGLE_CLOUD_PROJECT_ID environment variable is required');
  }

  return new GoogleCloudKMS(config);
}
