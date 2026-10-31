// Exit 0 when this Node process was started through Mad Elf.
// The environment variable is set by the shim before Node's main runs.
// A child that inherited the variable also sees it; `build/mad-elf detect <pid>`
// checks the executable itself and does not treat an inherited variable as a match.
const throughMadElf = process.env.MADELF_SHIM === "1";
console.log(JSON.stringify({
  madElf: throughMadElf,
  execArgv: process.execArgv,
  profile: process.env.MADELF_PROFILE || null,
}));
process.exit(throughMadElf ? 0 : 1);
