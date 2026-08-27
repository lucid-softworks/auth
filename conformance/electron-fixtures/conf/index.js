export default class Conf {
  #values = new Map();

  get(key, fallback) {
    return this.#values.get(key) ?? fallback;
  }

  set(key, value) {
    this.#values.set(key, value);
  }
}
