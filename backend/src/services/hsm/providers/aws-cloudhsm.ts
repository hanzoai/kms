// AWS CloudHSM Provider for KMS
// Supports AWS CloudHSM (FIPS 140-2 Level 3 validated)
// Uses PKCS#11 interface for cryptographic operations
// Integrates with AWS SDK for cluster management

import { HsmModule } from '../hsm-types';
import pkcs11js from 'pkcs11js';
import * as AWS from 'aws-sdk';
import * as fs from 'fs';

export interface AWSCloudHSMConfig {
  clusterID: string;           // AWS CloudHSM cluster ID
  libPath: string;             // /opt/cloudhsm/lib/libcloudhsm_pkcs11.so
  pin: string;                 // CU (Crypto User) PIN
  slot: number;                // Usually 0
  keyLabel: string;            // Key identifier
  region?: string;             // AWS region (e.g., us-east-1)
  hsmIPAddress?: string;       // HSM cluster IP (optional)
  enableHealthCheck?: boolean; // Enable cluster health check (default: true)
}

export interface AWSCloudHSMClusterInfo {
  state: string;
  hsms: number;
  vpc: string;
  subnets: string[];
  certificateFingerprint?: string;
}

export interface AWSCloudHSMHealthStatus {
  clusterActive: boolean;
  sessionActive: boolean;
  hsmCount: number;
  lastCheckTime: Date;
}

/**
 * AWS CloudHSM implementation using PKCS#11 interface
 * Provides FIPS 140-2 Level 3 validated hardware security
 */
export class AWSCloudHSM implements HsmModule {
  private pkcs11: any;
  private config: AWSCloudHSMConfig;
  private session: any;
  private cloudhsmClient: AWS.CloudHSMV2;
  private isInitialized: boolean = false;
  private lastHealthCheck?: AWSCloudHSMHealthStatus;

  constructor(config: AWSCloudHSMConfig) {
    this.config = {
      region: 'us-east-1',
      enableHealthCheck: true,
      ...config
    };
    this.pkcs11 = new pkcs11js.PKCS11();

    // Initialize AWS SDK client
    this.cloudhsmClient = new AWS.CloudHSMV2({
      region: this.config.region
    });
  }

  /**
   * Initialize AWS CloudHSM connection
   * Verifies cluster is active, loads PKCS#11 library, opens session, and performs login
   */
  async initialize(): Promise<void> {
    try {
      // Verify cluster is active
      if (this.config.enableHealthCheck) {
        await this.verifyClusterActive();
      }

      // Verify library exists
      if (!fs.existsSync(this.config.libPath)) {
        throw new Error(
          `AWS CloudHSM PKCS#11 library not found at ${this.config.libPath}. ` +
          'Install CloudHSM client: https://docs.aws.amazon.com/cloudhsm/latest/userguide/install-and-configure-client-linux.html'
        );
      }

      // Load CloudHSM PKCS#11 library
      this.pkcs11.load(this.config.libPath);
      this.pkcs11.C_Initialize();

      // Get available slots
      const slots = this.pkcs11.C_GetSlotList(true);
      if (!slots || slots.length === 0) {
        throw new Error(
          'No AWS CloudHSM slots found. Verify:\n' +
          '1. CloudHSM client is configured (/opt/cloudhsm/etc/cloudhsm_client.cfg)\n' +
          '2. HSM cluster IP is accessible\n' +
          '3. Network connectivity to cluster'
        );
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
      console.log(`AWS CloudHSM Slot Info: ${JSON.stringify(slotInfo)}`);

      // Get token info
      const tokenInfo = this.pkcs11.C_GetTokenInfo(slot);
      console.log(`AWS CloudHSM Token Info: ${JSON.stringify(tokenInfo)}`);

      // Open session
      this.session = this.pkcs11.C_OpenSession(
        slot,
        pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
      );

      // Login as Crypto User (CU)
      this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, this.config.pin);

      this.isInitialized = true;

      // Perform initial health check
      if (this.config.enableHealthCheck) {
        await this.healthCheck();
      }

      console.log('AWS CloudHSM initialized successfully');
    } catch (error) {
      this.isInitialized = false;
      throw new Error(`Failed to initialize AWS CloudHSM: ${error.message}`);
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
      console.log('AWS CloudHSM finalized successfully');
    } catch (error) {
      console.error(`Error finalizing AWS CloudHSM: ${error.message}`);
    }
  }

  /**
   * Get underlying PKCS#11 module
   */
  getModule(): any {
    if (!this.isInitialized) {
      throw new Error('AWS CloudHSM not initialized. Call initialize() first.');
    }
    return this.pkcs11;
  }

  /**
   * AWS-specific: Verify cluster is active
   * Throws error if cluster is not in ACTIVE state
   */
  private async verifyClusterActive(): Promise<void> {
    try {
      const result = await this.cloudhsmClient.describeClusters({
        Filters: {
          clusterIds: [this.config.clusterID]
        }
      }).promise();

      if (!result.Clusters || result.Clusters.length === 0) {
        throw new Error(`Cluster ${this.config.clusterID} not found`);
      }

      const cluster = result.Clusters[0];
      if (cluster.State !== 'ACTIVE') {
        throw new Error(
          `Cluster ${this.config.clusterID} is not active. ` +
          `Current state: ${cluster.State}. ` +
          'Cluster must be in ACTIVE state to perform operations.'
        );
      }

      // Verify cluster has HSMs
      if (!cluster.Hsms || cluster.Hsms.length === 0) {
        throw new Error(
          `Cluster ${this.config.clusterID} has no HSMs. ` +
          'Add at least one HSM to the cluster.'
        );
      }

      // Count active HSMs
      const activeHSMs = cluster.Hsms.filter(hsm => hsm.State === 'ACTIVE');
      if (activeHSMs.length === 0) {
        throw new Error(
          `Cluster ${this.config.clusterID} has no active HSMs. ` +
          'At least one HSM must be in ACTIVE state.'
        );
      }

      console.log(
        `AWS CloudHSM cluster ${this.config.clusterID} verified: ` +
        `${activeHSMs.length} active HSM(s)`
      );
    } catch (error) {
      if (error.code === 'AccessDeniedException') {
        throw new Error(
          'AWS IAM permissions insufficient. Required permissions:\n' +
          '- cloudhsm:DescribeClusters\n' +
          '- cloudhsm:ListTags'
        );
      }
      throw error;
    }
  }

  /**
   * AWS-specific: Get cluster information
   * Returns cluster state, HSM count, VPC, and subnets
   */
  async getClusterInfo(): Promise<AWSCloudHSMClusterInfo> {
    try {
      const result = await this.cloudhsmClient.describeClusters({
        Filters: {
          clusterIds: [this.config.clusterID]
        }
      }).promise();

      const cluster = result.Clusters?.[0];
      if (!cluster) {
        throw new Error(`Cluster ${this.config.clusterID} not found`);
      }

      // Get certificate fingerprint if available
      let certificateFingerprint: string | undefined;
      if (cluster.Certificates?.ClusterCertificate) {
        // Extract fingerprint from certificate (simplified)
        certificateFingerprint = 'Available';
      }

      return {
        state: cluster.State || 'UNKNOWN',
        hsms: cluster.Hsms?.length || 0,
        vpc: cluster.VpcId || '',
        subnets: cluster.SubnetMapping ? Object.values(cluster.SubnetMapping) : [],
        certificateFingerprint
      };
    } catch (error) {
      throw new Error(`Failed to get cluster info: ${error.message}`);
    }
  }

  /**
   * AWS-specific: Create HSM in cluster for high availability
   * Returns HSM ID
   */
  async createHSM(availabilityZone: string): Promise<string> {
    try {
      const result = await this.cloudhsmClient.createHsm({
        ClusterId: this.config.clusterID,
        AvailabilityZone: availabilityZone
      }).promise();

      const hsmId = result.Hsm?.HsmId || '';
      console.log(`Created HSM ${hsmId} in cluster ${this.config.clusterID}`);
      return hsmId;
    } catch (error) {
      if (error.code === 'AccessDeniedException') {
        throw new Error(
          'AWS IAM permissions insufficient. Required: cloudhsm:CreateHsm'
        );
      }
      throw new Error(`Failed to create HSM: ${error.message}`);
    }
  }

  /**
   * AWS-specific: Delete HSM from cluster
   * Use for scaling down or maintenance
   */
  async deleteHSM(hsmId: string): Promise<void> {
    try {
      await this.cloudhsmClient.deleteHsm({
        ClusterId: this.config.clusterID,
        HsmId: hsmId
      }).promise();

      console.log(`Deleted HSM ${hsmId} from cluster ${this.config.clusterID}`);
    } catch (error) {
      if (error.code === 'AccessDeniedException') {
        throw new Error(
          'AWS IAM permissions insufficient. Required: cloudhsm:DeleteHsm'
        );
      }
      throw new Error(`Failed to delete HSM: ${error.message}`);
    }
  }

  /**
   * Health check for cluster and session
   * Returns comprehensive health status
   */
  async healthCheck(): Promise<AWSCloudHSMHealthStatus> {
    try {
      // Check cluster status via AWS API
      const clusterInfo = await this.getClusterInfo();
      const clusterActive = clusterInfo.state === 'ACTIVE';

      // Check session status via PKCS#11
      let sessionActive = false;
      try {
        if (this.isInitialized && this.session) {
          const sessionInfo = this.pkcs11.C_GetSessionInfo(this.session);
          sessionActive = sessionInfo.state !== undefined;
        }
      } catch (error) {
        console.error(`Session health check failed: ${error.message}`);
      }

      this.lastHealthCheck = {
        clusterActive,
        sessionActive,
        hsmCount: clusterInfo.hsms,
        lastCheckTime: new Date()
      };

      return this.lastHealthCheck;
    } catch (error) {
      throw new Error(`Health check failed: ${error.message}`);
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
      throw new Error(
        `Key with label "${this.config.keyLabel}" not found. ` +
        'Generate key using cloudhsm_mgmt_util or key_mgmt_util.'
      );
    }

    return handles[0];
  }

  /**
   * Encrypt data using HSM key (AES-GCM)
   */
  async encrypt(data: Buffer): Promise<Buffer> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Find encryption key
      const keyHandle = this.findKeyByLabel(pkcs11js.CKO_SECRET_KEY);

      // Generate random IV (12 bytes for GCM)
      const iv = Buffer.alloc(12);
      this.pkcs11.C_GenerateRandom(this.session, iv);

      // Initialize encryption (AES-GCM)
      const mechanism = {
        mechanism: pkcs11js.CKM_AES_GCM,
        parameter: {
          iv,
          aad: Buffer.alloc(0),
          tagBits: 128
        }
      };
      this.pkcs11.C_EncryptInit(this.session, mechanism, keyHandle);

      // Encrypt data
      const encrypted = this.pkcs11.C_Encrypt(
        this.session,
        data,
        Buffer.alloc(data.length + 16) // Data + GCM tag
      );

      // Prepend IV to encrypted data
      return Buffer.concat([iv, Buffer.from(encrypted)]);
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using HSM key (AES-GCM)
   */
  async decrypt(data: Buffer): Promise<Buffer> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Extract IV (first 12 bytes)
      if (data.length < 12) {
        throw new Error('Invalid encrypted data: too short');
      }
      const iv = data.slice(0, 12);
      const ciphertext = data.slice(12);

      // Find decryption key
      const keyHandle = this.findKeyByLabel(pkcs11js.CKO_SECRET_KEY);

      // Initialize decryption (AES-GCM)
      const mechanism = {
        mechanism: pkcs11js.CKM_AES_GCM,
        parameter: {
          iv,
          aad: Buffer.alloc(0),
          tagBits: 128
        }
      };
      this.pkcs11.C_DecryptInit(this.session, mechanism, keyHandle);

      // Decrypt data
      const decrypted = this.pkcs11.C_Decrypt(
        this.session,
        ciphertext,
        Buffer.alloc(ciphertext.length)
      );

      return Buffer.from(decrypted);
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Sign data using HSM private key (ECDSA SHA-256)
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
   * Verify signature using HSM public key (ECDSA SHA-256)
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
   * Generate new AES key in HSM
   * Returns key handle
   */
  async generateAESKey(keySize: 128 | 192 | 256 = 256): Promise<any> {
    try {
      if (!this.isInitialized) {
        throw new Error('HSM not initialized');
      }

      // Define key generation mechanism
      const mechanism = { mechanism: pkcs11js.CKM_AES_KEY_GEN };

      // Key template
      const template = [
        { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_SECRET_KEY },
        { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_AES },
        { type: pkcs11js.CKA_TOKEN, value: true },
        { type: pkcs11js.CKA_ENCRYPT, value: true },
        { type: pkcs11js.CKA_DECRYPT, value: true },
        { type: pkcs11js.CKA_VALUE_LEN, value: keySize / 8 },
        { type: pkcs11js.CKA_LABEL, value: this.config.keyLabel }
      ];

      // Generate key
      const keyHandle = this.pkcs11.C_GenerateKey(
        this.session,
        mechanism,
        template
      );

      console.log(`Generated AES-${keySize} key with label: ${this.config.keyLabel}`);
      return keyHandle;
    } catch (error) {
      throw new Error(`AES key generation failed: ${error.message}`);
    }
  }

  /**
   * Generate new EC key pair in HSM (P-256)
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

      console.log(`Generated EC key pair with label: ${this.config.keyLabel}`);
      return {
        publicKey: keys.publicKey,
        privateKey: keys.privateKey
      };
    } catch (error) {
      throw new Error(`Key pair generation failed: ${error.message}`);
    }
  }

  /**
   * Check if HSM is initialized
   */
  isActive(): boolean {
    return this.isInitialized;
  }

  /**
   * Get last health check result
   */
  getLastHealthCheck(): AWSCloudHSMHealthStatus | undefined {
    return this.lastHealthCheck;
  }
}

/**
 * Factory function to create AWS CloudHSM instance from environment variables
 */
export function createAWSCloudHSM(): AWSCloudHSM {
  const config: AWSCloudHSMConfig = {
    clusterID: process.env.AWS_CLOUDHSM_CLUSTER_ID || '',
    libPath: process.env.AWS_CLOUDHSM_LIB_PATH || '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so',
    pin: process.env.AWS_CLOUDHSM_PIN || '',
    slot: parseInt(process.env.HSM_SLOT || '0', 10),
    keyLabel: process.env.HSM_KEY_LABEL || 'lux-kms-key',
    region: process.env.AWS_REGION || 'us-east-1',
    hsmIPAddress: process.env.AWS_CLOUDHSM_IP,
    enableHealthCheck: process.env.AWS_CLOUDHSM_HEALTH_CHECK !== 'false'
  };

  // Validate configuration
  if (!config.clusterID) {
    throw new Error('AWS_CLOUDHSM_CLUSTER_ID environment variable is required');
  }
  if (!config.pin) {
    throw new Error('AWS_CLOUDHSM_PIN environment variable is required');
  }

  return new AWSCloudHSM(config);
}
