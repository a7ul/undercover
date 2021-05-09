const tests = [];

export function test(name, fn) {
  tests.push({ name, fn });
}

export function run() {
  tests.forEach((t) => {
    try {
      t.fn();
      console.log("✅", t.name);
    } catch (e) {
      console.log("❌", t.name);
      console.log(e.stack);
    }
  });
}
