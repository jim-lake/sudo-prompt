var Node = {
  child: require('child_process'),
  crypto: require('crypto'),
  fs: require('fs'),
  os: require('os'),
  path: require('path'),
  process: process,
  util: require('util')
};

function Attempt(instance, end) {
  var platform = Node.process.platform;
  if (platform === 'darwin') return Mac(instance, end);
  if (platform === 'linux') return Linux(instance, end);
  if (platform === 'win32') return Windows(instance, end);
  end(new Error('Platform not yet supported.'));
}

function EscapeDoubleQuotes(string) {
  if (typeof string !== 'string') throw new Error('Expected a string.');
  return string.replace(/"/g, '\\"');
}

function Exec() {
  if (arguments.length < 1 || arguments.length > 3) {
    throw new Error('Wrong number of arguments.');
  }
  var command = arguments[0];
  var options = {};
  var end = function() {};
  if (typeof command !== 'string') {
    throw new Error('Command should be a string.');
  }
  if (arguments.length === 2) {
    if (Node.util.isObject(arguments[1])) {
      options = arguments[1];
    } else if (Node.util.isFunction(arguments[1])) {
      end = arguments[1];
    } else {
      throw new Error('Expected options or callback.');
    }
  } else if (arguments.length === 3) {
    if (Node.util.isObject(arguments[1])) {
      options = arguments[1];
    } else {
      throw new Error('Expected options to be an object.');
    }
    if (Node.util.isFunction(arguments[2])) {
      end = arguments[2];
    } else {
      throw new Error('Expected callback to be a function.');
    }
  }
  if (/^sudo/i.test(command)) {
    return end(new Error('Command should not be prefixed with "sudo".'));
  }
  if (typeof options.name === 'undefined') {
    var title = Node.process.title;
    if (ValidName(title)) {
      options.name = title;
    } else {
      return end(new Error('process.title cannot be used as a valid name.'));
    }
  } else if (!ValidName(options.name)) {
    var error = '';
    error += 'options.name must be alphanumeric only ';
    error += '(spaces are allowed) and <= 70 characters.';
    return end(new Error(error));
  }
  if (typeof options.icns !== 'undefined') {
    if (typeof options.icns !== 'string') {
      return end(new Error('options.icns must be a string if provided.'));
    } else if (options.icns.trim().length === 0) {
      return end(new Error('options.icns must not be empty if provided.'));
    }
  }
  if (typeof options.env !== 'undefined') {
    if (typeof options.env !== 'object') {
      return end(new Error('options.env must be an object if provided.'));
    } else if (Object.keys(options.env).length === 0) {
      return end(new Error('options.env must not be empty if provided.'));
    } else {
      for (var key in options.env) {
        var value = options.env[key];
        if (typeof key !== 'string' || typeof value !== 'string') {
          return end(
            new Error('options.env environment variables must be strings.')
          );
        }
        // "Environment variable names used by the utilities in the Shell and
        // Utilities volume of IEEE Std 1003.1-2001 consist solely of uppercase
        // letters, digits, and the '_' (underscore) from the characters defined
        // in Portable Character Set and do not begin with a digit. Other
        // characters may be permitted by an implementation; applications shall
        // tolerate the presence of such names."
        if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
          return end(
            new Error(
              'options.env has an invalid environment variable name: ' +
              JSON.stringify(key)
            )
          );
        }
        if (/[\r\n]/.test(value)) {
          return end(
            new Error(
              'options.env has an invalid environment variable value: ' +
              JSON.stringify(value)
            )
          );
        }
      }
    }
  }
  var platform = Node.process.platform;
  if (platform !== 'darwin' && platform !== 'linux' && platform !== 'win32') {
    return end(new Error('Platform not yet supported.'));
  }
  var instance = {
    command: command,
    options: options,
    uuid: undefined,
    path: undefined
  };
  Attempt(instance, end);
}

function Linux(instance, end) {
  LinuxBinary(instance,
    function(error, binary) {
      if (error) return end(error);
      var command = [];
      // Preserve current working directory:
      command.push('cd "' + EscapeDoubleQuotes(Node.process.cwd()) + '";');
      // Export environment variables:
      for (var key in instance.options.env) {
        var value = instance.options.env[key];
        command.push('export ' + key + '="' + EscapeDoubleQuotes(value) + '";');
      }
      command.push('"' + EscapeDoubleQuotes(binary) + '"');
      if (/kdesudo/i.test(binary)) {
        command.push(
          '--comment',
          '"' + instance.options.name + ' wants to make changes. ' +
          'Enter your password to allow this."'
        );
        command.push('-d'); // Do not show the command to be run in the dialog.
        command.push('--');
      } else if (/pkexec/i.test(binary)) {
        command.push('--disable-internal-agent');
      }
      var magic = 'SUDOPROMPT\n';
      command.push(
        '/bin/bash -c "echo ' + EscapeDoubleQuotes(magic.trim()) + '; ' +
        EscapeDoubleQuotes(instance.command) +
        '"'
      );
      command = command.join(' ');
      Node.child.exec(command, { encoding: 'utf-8', maxBuffer: MAX_BUFFER },
        function(error, stdout, stderr) {
          // ISSUE 88:
          // We must distinguish between elevation errors and command errors.
          //
          // KDESUDO:
          // kdesudo provides no way to do this. We add a magic marker to know
          // if elevation succeeded. Any error thereafter is a command error.
          //
          // PKEXEC:
          // "Upon successful completion, the return value is the return value of
          // PROGRAM. If the calling process is not authorized or an
          // authorization could not be obtained through authentication or an
          // error occured, pkexec exits with a return value of 127. If the
          // authorization could not be obtained because the user dismissed the
          // authentication dialog, pkexec exits with a return value of 126."
          //
          // However, we do not rely on pkexec's return of 127 since our magic
          // marker is more reliable, and we already use it for kdesudo.
          var elevated = stdout && stdout.slice(0, magic.length) === magic;
          if (elevated) stdout = stdout.slice(magic.length);
          // Only normalize the error if it is definitely not a command error:
          // In other words, if we know that the command was never elevated.
          // We do not inspect error messages beyond NO_POLKIT_AGENT.
          // We cannot rely on English errors because of internationalization.
          if (error && !elevated) {
            if (/No authentication agent found/.test(stderr)) {
              error.message = NO_POLKIT_AGENT;
            } else {
              error.message = PERMISSION_DENIED;
            }
          }
          end(error, stdout, stderr);
        }
      );
    }
  );
}

function LinuxBinary(instance, end) {
  var index = 0;
  // We used to prefer gksudo over pkexec since it enabled a better prompt.
  // However, gksudo cannot run multiple commands concurrently.
  var paths = ['/usr/bin/kdesudo', '/usr/bin/pkexec'];
  function test() {
    if (index === paths.length) {
      return end(new Error('Unable to find pkexec or kdesudo.'));
    }
    var path = paths[index++];
    Node.fs.stat(path,
      function(error) {
        if (error) {
          if (error.code === 'ENOTDIR') return test();
          if (error.code === 'ENOENT') return test();
          end(error);
        } else {
          end(undefined, path);
        }
      }
    );
  }
  test();
}

function Mac(instance, callback) {
  var temp = Node.os.tmpdir();
  if (!temp) return callback(new Error('os.tmpdir() not defined.'));
  var user = Node.process.env.USER; // Applet shell scripts require $USER.
  if (!user) return callback(new Error('env[\'USER\'] not defined.'));
  UUID(instance,
    function(error, uuid) {
      if (error) return callback(error);
      instance.uuid = uuid;
      instance.path = Node.path.join(
        temp,
        instance.uuid,
        instance.options.name + '.app'
      );
      function end(error, stdout, stderr) {
        Remove(Node.path.dirname(instance.path),
          function(errorRemove) {
            if (error) return callback(error);
            if (errorRemove) return callback(errorRemove);
            callback(undefined, stdout, stderr);
          }
        );
      }
      MacApplet(instance,
        function(error, stdout, stderr) {
          if (error) return end(error, stdout, stderr);
          MacIcon(instance,
            function(error) {
              if (error) return end(error);
              MacPropertyList(instance,
                function(error, stdout, stderr) {
                  if (error) return end(error, stdout, stderr);
                  MacCommand(instance,
                    function(error) {
                      if (error) return end(error);
                      MacOpen(instance,
                        function(error, stdout, stderr) {
                          if (error) return end(error, stdout, stderr);
                          MacResult(instance, end);
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
}

function MacApplet(instance, end) {
  var parent = Node.path.dirname(instance.path);
  Node.fs.mkdir(parent,
    function(error) {
      if (error) return end(error);
      var zip = Node.path.join(parent, 'sudo-prompt-applet.zip');
      Node.fs.writeFile(zip, APPLET, 'base64',
        function(error) {
          if (error) return end(error);
          var command = [];
          command.push('/usr/bin/unzip');
          command.push('-o'); // Overwrite any existing applet.
          command.push('"' + EscapeDoubleQuotes(zip) + '"');
          command.push('-d "' + EscapeDoubleQuotes(instance.path) + '"');
          command = command.join(' ');
          Node.child.exec(command, { encoding: 'utf-8' }, end);
        }
      );
    }
  );
}

function MacCommand(instance, end) {
  var path = Node.path.join(
    instance.path,
    'Contents',
    'MacOS',
    'sudo-prompt-command'
  );
  var script = [];
  // Preserve current working directory:
  // We do this for commands that rely on relative paths.
  // This runs in a subshell and will not change the cwd of sudo-prompt-script.
  script.push('cd "' + EscapeDoubleQuotes(Node.process.cwd()) + '"');
  // Export environment variables:
  for (var key in instance.options.env) {
    var value = instance.options.env[key];
    script.push('export ' + key + '="' + EscapeDoubleQuotes(value) + '"');
  }
  script.push(instance.command);
  script = script.join('\n');
  Node.fs.writeFile(path, script, 'utf-8', end);
}

function MacIcon(instance, end) {
  if (!instance.options.icns) return end();
  Node.fs.readFile(instance.options.icns,
    function(error, buffer) {
      if (error) return end(error);
      var icns = Node.path.join(
        instance.path,
        'Contents',
        'Resources',
        'applet.icns'
      );
      Node.fs.writeFile(icns, buffer, end);
    }
  );
}

function MacOpen(instance, end) {
  // We must run the binary directly so that the cwd will apply.
  var binary = Node.path.join(instance.path, 'Contents', 'MacOS', 'applet');
  // We must set the cwd so that the AppleScript can find the shell scripts.
  var options = {
    cwd: Node.path.dirname(binary),
    encoding: 'utf-8'
  };
  // We use the relative path rather than the absolute path. The instance.path
  // may contain spaces which the cwd can handle, but which exec() cannot.
  Node.child.exec('./' + Node.path.basename(binary), options, end);
}

function MacPropertyList(instance, end) {
  // Value must be in single quotes (not double quotes) according to man entry.
  // e.g. defaults write com.companyname.appname "Default Color" '(255, 0, 0)'
  // The defaults command will be changed in an upcoming major release to only
  // operate on preferences domains. General plist manipulation utilities will
  // be folded into a different command-line program.
  var plist = Node.path.join(instance.path, 'Contents', 'Info.plist');
  var path = EscapeDoubleQuotes(plist);
  var key = EscapeDoubleQuotes('CFBundleName');
  var value = instance.options.name + ' Password Prompt';
  if (/'/.test(value)) {
    return end(new Error('Value should not contain single quotes.'));
  }
  var command = [];
  command.push('/usr/bin/defaults');
  command.push('write');
  command.push('"' + path + '"');
  command.push('"' + key + '"');
  command.push("'" + value + "'"); // We must use single quotes for value.
  command = command.join(' ');
  Node.child.exec(command, { encoding: 'utf-8' }, end);
}

function MacResult(instance, end) {
  var cwd = Node.path.join(instance.path, 'Contents', 'MacOS');
  Node.fs.readFile(Node.path.join(cwd, 'code'), 'utf-8',
    function(error, code) {
      if (error) {
        if (error.code === 'ENOENT') return end(new Error(PERMISSION_DENIED));
        end(error);
      } else {
        Node.fs.readFile(Node.path.join(cwd, 'stdout'), 'utf-8',
          function(error, stdout) {
            if (error) return end(error);
            Node.fs.readFile(Node.path.join(cwd, 'stderr'), 'utf-8',
              function(error, stderr) {
                if (error) return end(error);
                code = parseInt(code.trim(), 10); // Includes trailing newline.
                if (code === 0) {
                  end(undefined, stdout, stderr);
                } else {
                  error = new Error(
                    'Command failed: ' + instance.command + '\n' + stderr
                  );
                  error.code = code;
                  end(error, stdout, stderr);
                }
              }
            );
          }
        );
      }
    }
  );
}

function Remove(path, end) {
  if (typeof path !== 'string' || !path.trim()) {
    return end(new Error('Argument path not defined.'));
  }
  var command = [];
  if (Node.process.platform === 'win32') {
    if (/"/.test(path)) {
      return end(new Error('Argument path cannot contain double-quotes.'));
    }
    command.push('rmdir /s /q "' + path + '"');
  } else {
    command.push('/bin/rm');
    command.push('-rf');
    command.push('"' + EscapeDoubleQuotes(Node.path.normalize(path)) + '"');
  }
  command = command.join(' ');
  Node.child.exec(command, { encoding: 'utf-8' }, end);
}

function UUID(instance, end) {
  Node.crypto.randomBytes(256,
    function(error, random) {
      if (error) random = Date.now() + '' + Math.random();
      var hash = Node.crypto.createHash('SHA256');
      hash.update('sudo-prompt-3');
      hash.update(instance.options.name);
      hash.update(instance.command);
      hash.update(random);
      var uuid = hash.digest('hex').slice(-32);
      if (!uuid || typeof uuid !== 'string' || uuid.length !== 32) {
        // This is critical to ensure we don't remove the wrong temp directory.
        return end(new Error('Expected a valid UUID.'));
      }
      end(undefined, uuid);
    }
  );
}

function ValidName(string) {
  // We use 70 characters as a limit to side-step any issues with Unicode
  // normalization form causing a 255 character string to exceed the fs limit.
  if (!/^[a-z0-9 ]+$/i.test(string)) return false;
  if (string.trim().length === 0) return false;
  if (string.length > 70) return false;
  return true;
}

function Windows(instance, callback) {
  var temp = Node.os.tmpdir();
  if (!temp) return callback(new Error('os.tmpdir() not defined.'));
  UUID(instance,
    function(error, uuid) {
      if (error) return callback(error);
      instance.uuid = uuid;
      instance.path = Node.path.join(temp, instance.uuid);
      if (/"/.test(instance.path)) {
        // We expect double quotes to be reserved on Windows.
        // Even so, we test for this and abort if they are present.
        return callback(
          new Error('instance.path cannot contain double-quotes.')
        );
      }
      instance.pathElevate = Node.path.join(instance.path, 'elevate.vbs');
      instance.pathExecute = Node.path.join(instance.path, 'execute.bat');
      instance.pathCommand = Node.path.join(instance.path, 'command.bat');
      instance.pathStdout = Node.path.join(instance.path, 'stdout');
      instance.pathStderr = Node.path.join(instance.path, 'stderr');
      instance.pathStatus = Node.path.join(instance.path, 'status');
      Node.fs.mkdir(instance.path,
        function(error) {
          if (error) return callback(error);
          function end(error, stdout, stderr) {
            Remove(instance.path,
              function(errorRemove) {
                if (error) return callback(error);
                if (errorRemove) return callback(errorRemove);
                callback(undefined, stdout, stderr);
              }
            );
          }
          WindowsWriteExecuteScript(instance,
            function(error) {
              if (error) return end(error);
              WindowsWriteCommandScript(instance,
                function(error) {
                  if (error) return end(error);
                  WindowsElevate(instance,
                    function(error, stdout, stderr) {
                      if (error) return end(error, stdout, stderr);
                      WindowsWaitForStatus(instance,
                        function(error) {
                          if (error) return end(error);
                          WindowsResult(instance, end);
                        }
                      );
                    }
                  );
                }
              );
            }
          );
        }
      );
    }
  );
}

function WindowsElevate(instance, end) {
  // We used to use this for executing elevate.vbs:
  // var command = 'cscript.exe //NoLogo "' + instance.pathElevate + '"';
  var command = [];
  command.push('powershell.exe');
  command.push('Start-Process');
  command.push('-FilePath');
  // Escape characters for cmd using double quotes:
  // Escape characters for PowerShell using single quotes:
  // Escape single quotes for PowerShell using backtick:
  // See: https://ss64.com/ps/syntax-esc.html
  command.push('"\'' + instance.pathExecute.replace(/'/g, "`'") + '\'"');
  command.push('-WindowStyle hidden');
  command.push('-Verb runAs');
  command = command.join(' ');
  var child = Node.child.exec(command, { encoding: 'utf-8' },
    function(error, stdout, stderr) {
      // We used to return PERMISSION_DENIED only for error messages containing
      // the string 'canceled by the user'. However, Windows internationalizes
      // error messages (issue 96) so now we must assume all errors here are
      // permission errors. This seems reasonable, given that we already run the
      // user's command in a subshell.
      if (error) return end(new Error(PERMISSION_DENIED), stdout, stderr);
      end();
    }
  );
  child.stdin.end(); // Otherwise PowerShell waits indefinitely on Windows 7.
}

function WindowsResult(instance, end) {
  Node.fs.readFile(instance.pathStatus, 'utf-8',
    function(error, code) {
      if (error) return end(error);
      Node.fs.readFile(instance.pathStdout, 'utf-8',
        function(error, stdout) {
          if (error) return end(error);
          Node.fs.readFile(instance.pathStderr, 'utf-8',
            function(error, stderr) {
              if (error) return end(error);
              code = parseInt(code.trim(), 10);
              if (code === 0) {
                end(undefined, stdout, stderr);
              } else {
                error = new Error(
                  'Command failed: ' + instance.command + '\r\n' + stderr
                );
                error.code = code;
                end(error, stdout, stderr);
              }
            }
          );
        }
      );
    }
  );
}

function WindowsWaitForStatus(instance, end) {
  // VBScript cannot wait for the elevated process to finish so we have to poll.
  // VBScript cannot return error code if user does not grant permission.
  // PowerShell can be used to elevate and wait on Windows 10.
  // PowerShell can be used to elevate on Windows 7 but it cannot wait.
  // powershell.exe Start-Process cmd.exe -Verb runAs -Wait
  Node.fs.stat(instance.pathStatus,
    function(error, stats) {
      if ((error && error.code === 'ENOENT') || stats.size < 2) {
        // Retry if file does not exist or is not finished writing.
        // We expect a file size of 2. That should cover at least "0\r".
        // We use a 1 second timeout to keep a light footprint for long-lived
        // sudo-prompt processes.
        setTimeout(
          function() {
            // If administrator has no password and user clicks Yes, then
            // PowerShell returns no error and execute (and command) never runs.
            // We check that command output has been redirected to stdout file:
            Node.fs.stat(instance.pathStdout,
              function(error) {
                if (error) return end(new Error(PERMISSION_DENIED));
                WindowsWaitForStatus(instance, end);
              }
            );
          },
          1000
        );
      } else if (error) {
        end(error);
      } else {
        end();
      }
    }
  );
}

function WindowsWriteCommandScript(instance, end) {
  var cwd = Node.process.cwd();
  if (/"/.test(cwd)) {
    // We expect double quotes to be reserved on Windows.
    // Even so, we test for this and abort if they are present.
    return end(new Error('process.cwd() cannot contain double-quotes.'));
  }
  var script = [];
  script.push('@echo off');
  // Set code page to UTF-8:
  script.push('chcp 65001>nul');
  // Preserve current working directory:
  // We pass /d as an option in case the cwd is on another drive (issue 70).
  script.push('cd /d "' + cwd + '"');
  // Export environment variables:
  for (var key in instance.options.env) {
    // "The characters <, >, |, &, ^ are special command shell characters, and
    // they must be preceded by the escape character (^) or enclosed in
    // quotation marks. If you use quotation marks to enclose a string that
    // contains one of the special characters, the quotation marks are set as
    // part of the environment variable value."
    // In other words, Windows assigns everything that follows the equals sign
    // to the value of the variable, whereas Unix systems ignore double quotes.
    var value = instance.options.env[key];
    script.push('set ' + key + '=' + value.replace(/([<>\\|&^])/g, '^$1'));
  }
  script.push(instance.command);
  script = script.join('\r\n');
  Node.fs.writeFile(instance.pathCommand, script, 'utf-8', end);
}

function WindowsWriteElevateScript(instance, end) {
  // We do not use VBScript to elevate since it does not return an error if
  // the user does not grant permission. This is here for reference.
  // var script = [];
  // script.push('Set objShell = CreateObject("Shell.Application")');
  // script.push(
  // 'objShell.ShellExecute "' + instance.pathExecute + '", "", "", "runas", 0'
  // );
  // script = script.join('\r\n');
  // Node.fs.writeFile(instance.pathElevate, script, 'utf-8', end);
}

function WindowsWriteExecuteScript(instance, end) {
  var script = [];
  script.push('@echo off');
  script.push(
    'call "' + instance.pathCommand + '"' +
    ' > "' + instance.pathStdout + '" 2> "' + instance.pathStderr + '"'
  );
  script.push('(echo %ERRORLEVEL%) > "' + instance.pathStatus + '"');
  script = script.join('\r\n');
  Node.fs.writeFile(instance.pathExecute, script, 'utf-8', end);
}

module.exports.exec = Exec;

// We used to expect that applet.app would be included with this module.
// This could not be copied when sudo-prompt was packaged within an asar file.
// We now store applet.app as a zip file in base64 within index.js instead.
// To recreate: "zip -r ../applet.zip Contents" (with applet.app as CWD).
// The zip file must not include applet.app as the root directory so that we
// can extract it directly to the target app directory.
var APPLET = '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';

var PERMISSION_DENIED = 'User did not grant permission.';
var NO_POLKIT_AGENT = 'No polkit authentication agent found.';

// See issue 66:
var MAX_BUFFER = 134217728;
