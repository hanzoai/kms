export const isCloudDeployment = (): boolean => false;

/** @deprecated Use isCloudDeployment instead */
export const isHanzoCloud = isCloudDeployment;
