Here's how I configure my environment for Ghidra development:

1. Compile the wonderful [IntelliJ Ghidra](https://github.com/garyttierney/intellij-ghidra) plugin by [@garyttierney](https://github.com/garyttierney/) for the current IntelliJ IDEA version and install it from disk.

2. Inside of IJ IDEA, create a regular Gradle java project.
3. File > Project Structure > Facets > + > Ghidra
4. Fill out the ghidra installation path.
5. Run > Edit configurations > + > Ghidra Launcher
6. Select the project's JDK if it's not already in there.


7. Add the following to the top of your `build.gradle`...

> [!NOTE]
> This step is not necessary if you are cloning this repository, where `build.gradle` is already created.
> **This is only for if you want to start a new plugin from scratch.** If this is not your goal, then you can skip to step 8.

```
//----------------------START "DO NOT MODIFY" SECTION------------------------------
def ghidraInstallDir

if (System.env.GHIDRA_INSTALL_DIR) {
    ghidraInstallDir = System.env.GHIDRA_INSTALL_DIR
}
else if (project.hasProperty("GHIDRA_INSTALL_DIR")) {
    ghidraInstallDir = project.getProperty("GHIDRA_INSTALL_DIR")
}

if (ghidraInstallDir) {
    apply from: new File(ghidraInstallDir).getCanonicalPath() + "/support/buildExtension.gradle"
}
else {
    throw new GradleException("GHIDRA_INSTALL_DIR is not defined!")
}
//----------------------END "DO NOT MODIFY" SECTION-------------------------------
```
8. Create a `gradle.properties` file with this, for example:

```
GHIDRA_INSTALL_DIR=~/Desktop/ghidra_11.1.1_PUBLIC
```
