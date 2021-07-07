function extend(SuperClass) {
  return class ActorToken extends SuperClass {
    #payload;

    constructor(payload) {
      super(payload);
      this.#payload = {
        accountId: undefined,
        claims: undefined,
        'x5t#S256': undefined,
        ...payload,
      };
    }

    get accountId() {
      return this.#payload.accountId;
    }

    get sub() {
      return this.#payload.sub;
    }
  };
}

export default extend;
