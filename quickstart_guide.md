# HEBench - SEAL CPU Reference Backend - Quickstart Guide

## Benchmarking a Reference Backend

This guide will walk you through the steps of running the benchmark for the reference SEAL backend. Note the default configuration for this backend may take an extended amount of time on some systems. If you'd like to reduce the amount of workloads run, please refer to the [Test Harness User Guide](https://hebench.github.io/frontend/test_harness_usage_guide.html) and the [Benchmark Configuration File Reference](https://hebench.github.io/frontend/config_file_reference.html) on modifying backend configuration files.

1. Pick the SEAL backend repository from the list of [published backends](https://hebench.github.io/hebench_published_backends.html), or visit direct link to [SEAL backend repository](https://github.com/hebench/reference-seal-backend).

2. Check the [readme](https://github.com/hebench/reference-seal-backend/blob/main/README.md) for requirements to build the backend.
   Make sure the machine where the build will occur meets such requirements.

3. Clone the repo to your local machine<b>*</b>.

   Assume the repo will be cloned to the location contained in environment variable `$SEAL_BACKEND`.

   Note that repo URL may change. Obtain the correct URL from the GitHub repo itself.

```bash
cd $SEAL_BACKEND
git clone https://github.com/hebench/reference-seal-backend.git
```

<b>*</b>_Users must have, at least, read access to the GitHub repository. Otherwise, cloning and/or building steps may fail._

4. Build with default settings.

   The following commands will create a build directory, pull down all the required dependencies, build all dependencies and the backend itself, and install the backend and Test Harness.

```bash
cd $SEAL_BACKEND/reference-seal-backend
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=$SEAL_BACKEND/reference-seal-backend/install -DCMAKE_BUILD_TYPE=Release ..
make -j
make install
```

5. Create a directory to hold the report of the benchmark we are about to run:

```bash
mkdir $HOME/reference-seal-backend-report
```

6. Navigate to directory where the test harness was installed:

```bash
cd $SEAL_BACKEND/reference-seal-backend/install/bin
```

7. Run the benchmark by executing test_harness while pointing it to the shared library containing the compiled SEAL reference backend.

   If these instructions have been followed correctly, the shared library for the SEAL reference backend should have been installed in `$SEAL_BACKEND/reference-seal-backend/install/lib` .


```bash
./test_harness --backend_lib_path $SEAL_BACKEND/reference-seal-backend/install/lib/libhebench_seal_backend.so --report_root_path $HOME/reference-seal-backend-report
```

8. After the execution completes, the report will be saved to the specified location `$HOME/reference-seal-backend-report`.

   The report is a collection of `CSV` files organized in directories that represent the benchmark parameters used for each workload benchmarked. Each report has a `report.csv` file and, if the corresponding benchmark completed successfully, a `summary.csv` file in the same location. View the `summary.csv` for the readable information about the benchmark, or `report.csv` if the benchmark failed for the cause of failure.

<br/>

While this quickstart guide is specific to the SEAL Reference Backend, you may find a more general quickstart guide at the [HEBench Getting Started Page](https://hebench.github.io/quickstart_guide.html).

<br/>

Back to [HEBench Home](https://hebench.github.io/).
