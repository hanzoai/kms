declare module "ipaddr.js" {
  interface IPv4 {
    toString(): string;
    match(other: [IPv4 | IPv6, number]): boolean;
  }
  interface IPv6 {
    toString(): string;
    match(other: [IPv4 | IPv6, number]): boolean;
  }
  function parse(ip: string): IPv4 | IPv6;
  function parseCIDR(cidr: string): [IPv4 | IPv6, number];
  export default { parse, parseCIDR };
  export { IPv4, IPv6, parse, parseCIDR };
}
