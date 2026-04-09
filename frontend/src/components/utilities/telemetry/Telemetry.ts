/* eslint-disable */

class Capturer {
  capture(_item: string) {}
  identify(_id: string, _email?: string) {}
}

export default class Telemetry {
  static instance: Capturer;

  constructor() {
    if (!Telemetry.instance) {
      Telemetry.instance = new Capturer();
    }
  }

  getInstance() {
    return Telemetry.instance;
  }
}
