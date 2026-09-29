# LogLens
LogLens is a C++ log analyzer. It scans log files for security threats like brute-force attacks and password spraying, plus operational issues like error bursts, and shows the results in a dashboard.

To run: double-click loglens_gui.exe for the visual app, or run loglens.exe in a terminal for the command-line version.

To build the GUI yourself you need Dear ImGui and GLFW, then compile the files in src/gui with the modules in src/modules.
