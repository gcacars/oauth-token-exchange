function extend(SuperClass) {
  return class DelegatedToken extends SuperClass {
    static get IN_PAYLOAD() {
      return [...super.IN_PAYLOAD, 'act'];
    }
  };
}

export default extend;
