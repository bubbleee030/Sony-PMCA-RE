(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
    return;
  }
  root.CreativeLookOfflineApp = api;
  const start = function () {
    api.boot(document, root.localStorage);
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const STATE_FIELDS = [
    "schema_version",
    "offline_only",
    "target",
    "reference",
    "processing_binding",
    "selected_look",
    "screen",
    "orientation",
    "editing_axis",
    "custom_bases",
    "adjustments",
    "modes",
    "safety",
  ];
  const SCREENS = ["catalog", "custom_base", "editor", "axis_picker"];
  const SAFETY = {
    recovery_validated: false,
    camera_test_eligible: false,
    installable: false,
  };

  function fail(message) {
    throw new Error(message);
  }

  function clone(value) {
    return JSON.parse(JSON.stringify(value));
  }

  function sameMembers(actual, expected) {
    if (!actual || typeof actual !== "object" || Array.isArray(actual)) {
      return false;
    }
    const left = Object.keys(actual).sort();
    const right = expected.slice().sort();
    return left.length === right.length && left.every((key, index) => key === right[index]);
  }

  function exactObject(actual, expected) {
    if (!sameMembers(actual, Object.keys(expected))) {
      return false;
    }
    return Object.keys(expected).every((key) => actual[key] === expected[key]);
  }

  function validStringArray(value) {
    return Array.isArray(value) && value.length > 0 && value.every((item) => typeof item === "string" && item.length > 0);
  }

  function createCore(contract) {
    if (!contract || typeof contract !== "object") {
      fail("Creative Look contract is missing");
    }
    const builtIns = contract.built_in_looks;
    const customSlots = contract.custom_slots;
    const orientations = contract.orientations;
    const modes = contract.modes;
    const axes = contract.axes;
    if (!validStringArray(builtIns) || !validStringArray(customSlots) || !validStringArray(orientations) || !validStringArray(modes)) {
      fail("Creative Look contract membership is invalid");
    }
    if (!axes || typeof axes !== "object" || Array.isArray(axes) || Object.keys(axes).length !== 8) {
      fail("Creative Look axis contract is invalid");
    }
    Object.entries(axes).forEach(([axis, definition]) => {
      if (!axis || !definition || !Number.isInteger(definition.minimum) || !Number.isInteger(definition.maximum) || definition.minimum > definition.maximum) {
        fail("Creative Look axis range is invalid");
      }
    });
    const lookIds = builtIns.concat(customSlots);
    const axisIds = Object.keys(axes);

    function isModeUnavailable(state) {
      return state.modes.intelligent_auto || state.modes.picture_profile_not_off || state.modes.flexible_iso_log;
    }

    function resolvedBase(state) {
      return builtIns.includes(state.selected_look)
        ? state.selected_look
        : state.custom_bases[state.selected_look];
    }

    function axisAvailability(state, axis) {
      if (!axisIds.includes(axis)) {
        fail("axis identifier is invalid");
      }
      if (isModeUnavailable(state)) {
        return { enabled: false, reason: "CREATIVE_LOOK_MODE_UNAVAILABLE" };
      }
      if (axis === "saturation" && ["BW", "SE"].includes(resolvedBase(state))) {
        return { enabled: false, reason: "BW_SE_SATURATION_UNAVAILABLE" };
      }
      if (axis === "sharpness_range" && state.modes.movie_mode) {
        return { enabled: false, reason: "MOVIE_SHARPNESS_RANGE_UNAVAILABLE" };
      }
      return { enabled: true, reason: null };
    }

    function validateState(candidate) {
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate) || !sameMembers(candidate, STATE_FIELDS)) {
        fail("experience state fields are not exact");
      }
      if (
        candidate.schema_version !== 1 ||
        candidate.offline_only !== true ||
        candidate.target !== "ILCE-6400" ||
        candidate.reference !== "ILCE-7M5" ||
        candidate.processing_binding !== "UNBOUND_TARGET"
      ) {
        fail("experience identity or binding is invalid");
      }
      if (!lookIds.includes(candidate.selected_look)) {
        fail("selected look is invalid");
      }
      if (!SCREENS.includes(candidate.screen) || !orientations.includes(candidate.orientation)) {
        fail("screen or orientation is invalid");
      }
      if (candidate.editing_axis !== null && !axisIds.includes(candidate.editing_axis)) {
        fail("editing axis is invalid");
      }
      if ((candidate.screen === "axis_picker") !== (candidate.editing_axis !== null)) {
        fail("axis picker state is inconsistent");
      }
      if (!sameMembers(candidate.custom_bases, customSlots)) {
        fail("Custom slot membership is invalid");
      }
      customSlots.forEach((slot) => {
        const base = candidate.custom_bases[slot];
        if (base !== null && !builtIns.includes(base)) {
          fail("Custom base is invalid");
        }
      });
      if (!sameMembers(candidate.adjustments, lookIds)) {
        fail("adjustment membership is invalid");
      }
      lookIds.forEach((look) => {
        const values = candidate.adjustments[look];
        if (!sameMembers(values, axisIds)) {
          fail("axis membership is invalid");
        }
        axisIds.forEach((axis) => {
          const value = values[axis];
          const definition = axes[axis];
          if (value !== null && (!Number.isInteger(value) || value < definition.minimum || value > definition.maximum)) {
            fail("axis state is out of range");
          }
        });
      });
      if (!sameMembers(candidate.modes, modes) || modes.some((mode) => typeof candidate.modes[mode] !== "boolean")) {
        fail("mode state is invalid");
      }
      if (!exactObject(candidate.safety, SAFETY)) {
        fail("camera safety state is invalid");
      }
      if (
        customSlots.includes(candidate.selected_look) &&
        candidate.custom_bases[candidate.selected_look] === null &&
        ["editor", "axis_picker"].includes(candidate.screen)
      ) {
        fail("unconfigured Custom slot cannot be edited");
      }
      if (isModeUnavailable(candidate) && candidate.screen !== "catalog") {
        fail("unavailable Creative Look mode must remain on the catalog screen");
      }
      if (candidate.screen === "axis_picker" && !axisAvailability(candidate, candidate.editing_axis).enabled) {
        fail("restricted axis cannot remain open");
      }
      return clone(candidate);
    }

    function requireMode(state) {
      if (isModeUnavailable(state)) {
        fail("CREATIVE_LOOK_MODE_UNAVAILABLE");
      }
    }

    function transition(current, action) {
      const state = validateState(current);
      if (!action || typeof action !== "object" || typeof action.type !== "string") {
        fail("interaction action is invalid");
      }
      switch (action.type) {
        case "SET_ORIENTATION":
          if (!orientations.includes(action.orientation)) {
            fail("orientation is invalid");
          }
          state.orientation = action.orientation;
          break;
        case "SELECT_LOOK":
          requireMode(state);
          if (!lookIds.includes(action.look)) {
            fail("look identifier is invalid");
          }
          state.selected_look = action.look;
          state.editing_axis = null;
          state.screen = customSlots.includes(action.look) && state.custom_bases[action.look] === null
            ? "custom_base"
            : "editor";
          break;
        case "SELECT_CUSTOM_BASE":
          requireMode(state);
          if (!customSlots.includes(state.selected_look) || !builtIns.includes(action.base)) {
            fail("Custom base selection is invalid");
          }
          state.custom_bases[state.selected_look] = action.base;
          state.screen = "editor";
          state.editing_axis = null;
          break;
        case "OPEN_AXIS": {
          requireMode(state);
          const availability = axisAvailability(state, action.axis);
          if (!availability.enabled) {
            fail(availability.reason);
          }
          state.screen = "axis_picker";
          state.editing_axis = action.axis;
          break;
        }
        case "SET_AXIS": {
          requireMode(state);
          const availability = axisAvailability(state, action.axis);
          if (!availability.enabled) {
            fail(availability.reason);
          }
          const definition = axes[action.axis];
          if (
            action.value !== null &&
            (!Number.isInteger(action.value) || action.value < definition.minimum || action.value > definition.maximum)
          ) {
            fail("axis value is out of range");
          }
          state.adjustments[state.selected_look][action.axis] = action.value;
          state.screen = "editor";
          state.editing_axis = null;
          break;
        }
        case "RESET_SELECTED":
          requireMode(state);
          axisIds.forEach((axis) => {
            state.adjustments[state.selected_look][axis] = null;
          });
          break;
        case "BACK_TO_CATALOG":
          state.screen = "catalog";
          state.editing_axis = null;
          break;
        case "BACK":
          if (state.screen === "axis_picker") {
            state.screen = "editor";
            state.editing_axis = null;
          } else {
            state.screen = "catalog";
            state.editing_axis = null;
          }
          break;
        case "SET_MODE":
          if (!modes.includes(action.mode) || typeof action.value !== "boolean") {
            fail("mode update is invalid");
          }
          state.modes[action.mode] = action.value;
          if (isModeUnavailable(state)) {
            state.screen = "catalog";
            state.editing_axis = null;
          } else if (state.screen === "axis_picker" && !axisAvailability(state, state.editing_axis).enabled) {
            state.screen = "editor";
            state.editing_axis = null;
          }
          break;
        default:
          fail("interaction action is unsupported");
      }
      return validateState(state);
    }

    return {
      validateState,
      transition,
      axisAvailability,
      isModeUnavailable,
      resolvedBase,
      isModified: function (state, look) {
        return axisIds.some((axis) => state.adjustments[look][axis] !== null);
      },
      serialize: function (state) {
        return JSON.stringify(validateState(state));
      },
      builtIns: builtIns.slice(),
      customSlots: customSlots.slice(),
      lookIds: lookIds.slice(),
      axisIds: axisIds.slice(),
      orientations: orientations.slice(),
      modes: modes.slice(),
      axes: clone(axes),
    };
  }

  function element(documentObject, tag, className, text) {
    const node = documentObject.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  function button(documentObject, className, text, action, value) {
    const node = element(documentObject, "button", className, text);
    node.type = "button";
    node.dataset.action = action;
    if (value !== undefined) {
      node.dataset.value = value;
    }
    return node;
  }

  function boot(documentObject, storage) {
    const bootstrapNode = documentObject.getElementById("creative-look-bootstrap");
    const rootNode = documentObject.getElementById("creative-look-app");
    if (!bootstrapNode || !rootNode) {
      fail("offline prototype document is incomplete");
    }
    const bootstrap = JSON.parse(bootstrapNode.textContent);
    if (
      bootstrap.schema_version !== 1 ||
      bootstrap.offline_only !== true ||
      bootstrap.processing_binding !== "UNBOUND_TARGET" ||
      !exactObject(bootstrap.safety, SAFETY)
    ) {
      fail("offline prototype bootstrap is unsafe");
    }
    const contract = bootstrap.contract;
    const core = createCore(contract);
    let state = core.validateState(bootstrap.initial_state);
    let contextOpen = false;
    let toastTimer = null;

    try {
      const saved = storage.getItem(contract.storage_key);
      if (saved !== null) {
        state = core.validateState(JSON.parse(saved));
      }
    } catch (error) {
      state = core.validateState(bootstrap.initial_state);
    }

    function persist() {
      try {
        storage.setItem(contract.storage_key, core.serialize(state));
      } catch (error) {
        showToast("Browser persistence is unavailable; export state before closing.", "error");
      }
    }

    function showToast(message, level) {
      const toast = rootNode.querySelector(".toast");
      if (!toast) {
        return;
      }
      toast.textContent = message;
      toast.dataset.level = level || "info";
      toast.hidden = false;
      if (toastTimer !== null) {
        clearTimeout(toastTimer);
      }
      toastTimer = setTimeout(function () {
        toast.hidden = true;
      }, 2600);
    }

    function screenTitle() {
      if (state.screen === "catalog") return "Creative Look";
      if (state.screen === "custom_base") return state.selected_look + " · Choose base";
      if (state.screen === "axis_picker") return contract.axes[state.editing_axis].label;
      const label = core.customSlots.includes(state.selected_look)
        ? "Custom Look"
        : contract.look_labels[state.selected_look];
      return state.selected_look + " · " + label;
    }

    function swatchFor(look) {
      const resolved = core.builtIns.includes(look) ? look : state.custom_bases[look];
      return resolved ? contract.look_swatches[resolved] : null;
    }

    function applySwatch(node, look) {
      const swatch = swatchFor(look);
      if (swatch) {
        node.style.setProperty("--swatch-a", swatch.start);
        node.style.setProperty("--swatch-b", swatch.end);
      }
    }

    function renderTopbar(shell) {
      const topbar = element(documentObject, "header", "topbar");
      const title = element(documentObject, "div", "title-stack");
      title.append(element(documentObject, "p", "eyebrow", "α6400 · Offline native prototype"));
      title.append(element(documentObject, "h1", "screen-title", screenTitle()));
      topbar.append(title);

      const tools = element(documentObject, "div", "system-tools");
      core.orientations.forEach((orientation) => {
        const control = button(documentObject, "orientation-button", "", "orientation", orientation);
        control.dataset.value = orientation;
        control.setAttribute("aria-label", orientation.replaceAll("_", " "));
        control.setAttribute("aria-pressed", String(state.orientation === orientation));
        control.append(element(documentObject, "span", "orientation-symbol"));
        tools.append(control);
      });
      const context = button(documentObject, "icon-button", "CTX", "toggle-context");
      context.setAttribute("aria-label", "Toggle shooting context test controls");
      context.setAttribute("aria-expanded", String(contextOpen));
      tools.append(context);
      topbar.append(tools);
      shell.append(topbar);
    }

    function renderCatalog(content) {
      if (core.isModeUnavailable(state)) {
        content.append(element(documentObject, "p", "unavailable-banner", "Creative Look is unavailable in the current shooting context. Change Context settings to continue."));
      }
      const grid = element(documentObject, "div", "catalog-grid");
      core.lookIds.forEach((look) => {
        const card = button(documentObject, "look-card", "", "select-look", look);
        card.disabled = core.isModeUnavailable(state);
        card.setAttribute("aria-current", String(state.selected_look === look));
        const isCustom = core.customSlots.includes(look);
        const swatch = element(documentObject, "div", isCustom && !swatchFor(look) ? "custom-swatch" : "swatch");
        if (isCustom && !swatchFor(look)) {
          swatch.textContent = look.replace("Custom", "C");
        } else {
          applySwatch(swatch, look);
        }
        card.append(swatch);
        const meta = element(documentObject, "div", "look-meta");
        const copy = element(documentObject, "div", "look-copy");
        copy.append(element(documentObject, "span", "look-code", look));
        const subtitle = isCustom
          ? (state.custom_bases[look] ? "Base · " + state.custom_bases[look] : "Choose a base")
          : contract.look_labels[look];
        copy.append(element(documentObject, "span", "look-name", subtitle));
        meta.append(copy);
        if (core.isModified(state, look)) {
          const dot = element(documentObject, "span", "modified-dot");
          dot.setAttribute("aria-label", "Modified");
          meta.append(dot);
        }
        card.append(meta);
        grid.append(card);
      });
      content.append(grid);
    }

    function renderCustomBase(content) {
      const intro = element(documentObject, "div", "section-intro");
      const copy = element(documentObject, "div");
      copy.append(element(documentObject, "h2", "", "Choose a built-in starting point"));
      copy.append(element(documentObject, "p", "", "The Custom slot keeps its own eight adjustment values."));
      intro.append(copy);
      intro.append(button(documentObject, "nav-button", "Back", "back"));
      content.append(intro);
      const grid = element(documentObject, "div", "base-grid");
      core.builtIns.forEach((look) => {
        const card = button(documentObject, "base-card", "", "select-base", look);
        const swatch = element(documentObject, "div", "swatch");
        applySwatch(swatch, look);
        card.append(swatch);
        const meta = element(documentObject, "div", "look-meta");
        const copyNode = element(documentObject, "div", "look-copy");
        copyNode.append(element(documentObject, "span", "look-code", look));
        copyNode.append(element(documentObject, "span", "look-name", contract.look_labels[look]));
        meta.append(copyNode);
        card.append(meta);
        grid.append(card);
      });
      content.append(grid);
    }

    function displayValue(value) {
      if (value === null) return "Default";
      return value > 0 ? "+" + value : String(value);
    }

    function renderEditor(content) {
      const layout = element(documentObject, "div", "editor-layout");
      const hero = element(documentObject, "section", "look-hero");
      const heroSwatch = element(documentObject, "div", "hero-swatch");
      applySwatch(heroSwatch, state.selected_look);
      hero.append(heroSwatch);
      const heroCopy = element(documentObject, "div", "hero-copy");
      heroCopy.append(element(documentObject, "h2", "hero-code", state.selected_look));
      const base = core.resolvedBase(state);
      heroCopy.append(element(documentObject, "p", "", core.customSlots.includes(state.selected_look) ? "Custom base · " + base : contract.look_labels[state.selected_look]));
      heroCopy.append(element(documentObject, "p", "", "Swatch is a navigation aid, not Sony color output."));
      hero.append(heroCopy);
      layout.append(hero);

      const panel = element(documentObject, "section", "axis-panel");
      const list = element(documentObject, "div", "axis-list");
      core.axisIds.forEach((axis) => {
        const availability = core.axisAvailability(state, axis);
        const row = button(documentObject, "axis-row", "", "open-axis", axis);
        row.disabled = !availability.enabled;
        row.title = availability.reason || contract.axes[axis].label;
        row.append(element(documentObject, "span", "axis-label", contract.axes[axis].label));
        row.append(element(documentObject, "span", "axis-range", contract.axes[axis].minimum + " … " + contract.axes[axis].maximum));
        const current = state.adjustments[state.selected_look][axis];
        row.append(element(documentObject, "span", current === null ? "axis-value" : "axis-value is-modified", availability.enabled ? displayValue(current) : "Unavailable"));
        list.append(row);
      });
      panel.append(list);
      const actions = element(documentObject, "div", "editor-actions");
      actions.append(button(documentObject, "tool-button", "Catalog", "catalog"));
      actions.append(button(documentObject, "tool-button primary", "Reset Look", "reset"));
      panel.append(actions);
      layout.append(panel);
      content.append(layout);
    }

    function renderAxisPicker(content) {
      const axis = state.editing_axis;
      const definition = contract.axes[axis];
      const intro = element(documentObject, "div", "section-intro");
      const copy = element(documentObject, "div");
      copy.append(element(documentObject, "h2", "", definition.label));
      copy.append(element(documentObject, "p", "", "Choose Default or an exact value from " + definition.minimum + " to " + definition.maximum + "."));
      intro.append(copy);
      intro.append(button(documentObject, "nav-button", "Back", "back"));
      content.append(intro);
      const grid = element(documentObject, "div", "value-grid");
      const current = state.adjustments[state.selected_look][axis];
      const values = [null];
      for (let value = definition.minimum; value <= definition.maximum; value += 1) {
        values.push(value);
      }
      values.forEach((value) => {
        const encoded = value === null ? "default" : String(value);
        const control = button(documentObject, "value-button", displayValue(value), "set-axis", encoded);
        control.dataset.axis = axis;
        control.setAttribute("aria-current", String(current === value));
        grid.append(control);
      });
      content.append(grid);
    }

    function renderContext(shell) {
      const panel = element(documentObject, "aside", "context-panel");
      panel.hidden = !contextOpen;
      panel.append(element(documentObject, "h2", "", "Shooting context"));
      panel.append(element(documentObject, "p", "", "Offline controls for exercising the reference restriction matrix."));
      core.modes.forEach((mode) => {
        const label = element(documentObject, "label", "mode-toggle");
        label.append(element(documentObject, "span", "", contract.mode_labels[mode]));
        const input = element(documentObject, "input");
        input.type = "checkbox";
        input.checked = state.modes[mode];
        input.dataset.action = "set-mode";
        input.dataset.value = mode;
        label.append(input);
        panel.append(label);
      });
      shell.append(panel);
    }

    function renderBottom(shell) {
      const bottom = element(documentObject, "footer", "bottom-bar");
      const boundary = element(documentObject, "div", "boundary-copy");
      boundary.append(element(documentObject, "strong", "", "OFFLINE ONLY · "));
      boundary.append(element(documentObject, "span", "", "Processing unbound · Recovery unverified · Not installable"));
      bottom.append(boundary);
      const tools = element(documentObject, "div", "utility-tools");
      tools.append(button(documentObject, "icon-button", "Import", "import"));
      tools.append(button(documentObject, "icon-button", "Export", "export"));
      bottom.append(tools);
      shell.append(bottom);
    }

    function render() {
      documentObject.body.dataset.orientation = state.orientation;
      rootNode.replaceChildren();
      const shell = element(documentObject, "section", "camera-shell");
      shell.dataset.offlineOnly = "true";
      shell.dataset.processingBinding = "UNBOUND_TARGET";
      renderTopbar(shell);
      const content = element(documentObject, "div", "content");
      const inner = element(documentObject, "div", "content-inner");
      if (state.screen === "catalog") renderCatalog(inner);
      if (state.screen === "custom_base") renderCustomBase(inner);
      if (state.screen === "editor") renderEditor(inner);
      if (state.screen === "axis_picker") renderAxisPicker(inner);
      content.append(inner);
      shell.append(content);
      renderBottom(shell);
      renderContext(shell);
      const fileInput = element(documentObject, "input", "file-input");
      fileInput.type = "file";
      fileInput.accept = "application/json,.json";
      fileInput.dataset.role = "state-import";
      shell.append(fileInput);
      const toast = element(documentObject, "div", "toast");
      toast.hidden = true;
      toast.setAttribute("role", "status");
      shell.append(toast);
      rootNode.append(shell);
    }

    function dispatch(action, message) {
      try {
        state = core.transition(state, action);
        persist();
        render();
        if (message) showToast(message, "info");
      } catch (error) {
        showToast(error.message, "error");
      }
    }

    rootNode.addEventListener("click", function (event) {
      const target = event.target.closest("[data-action]");
      if (!target || target.disabled) return;
      const action = target.dataset.action;
      const value = target.dataset.value;
      if (action === "orientation") dispatch({ type: "SET_ORIENTATION", orientation: value });
      if (action === "select-look") dispatch({ type: "SELECT_LOOK", look: value });
      if (action === "select-base") dispatch({ type: "SELECT_CUSTOM_BASE", base: value });
      if (action === "open-axis") dispatch({ type: "OPEN_AXIS", axis: value });
      if (action === "set-axis") dispatch({ type: "SET_AXIS", axis: target.dataset.axis, value: value === "default" ? null : Number(value) });
      if (action === "reset") dispatch({ type: "RESET_SELECTED" }, "Selected Look reset to unknown reference defaults.");
      if (action === "catalog") dispatch({ type: "BACK_TO_CATALOG" });
      if (action === "back") dispatch({ type: "BACK" });
      if (action === "toggle-context") {
        contextOpen = !contextOpen;
        render();
      }
      if (action === "import") rootNode.querySelector('[data-role="state-import"]').click();
      if (action === "export") {
        const blob = new Blob([JSON.stringify(core.validateState(state), null, 2) + "\n"], { type: "application/json" });
        const link = documentObject.createElement("a");
        link.download = "a6400-creative-look-state.json";
        link.href = URL.createObjectURL(blob);
        link.click();
        URL.revokeObjectURL(link.href);
        showToast("Strict offline state exported.", "info");
      }
    });

    rootNode.addEventListener("change", function (event) {
      const target = event.target;
      if (target.dataset.action === "set-mode") {
        dispatch({ type: "SET_MODE", mode: target.dataset.value, value: target.checked });
        return;
      }
      if (target.dataset.role !== "state-import" || !target.files || target.files.length !== 1) return;
      const file = target.files[0];
      if (file.size > 262144) {
        showToast("State file exceeds the 256 KiB limit.", "error");
        return;
      }
      const reader = new FileReader();
      reader.addEventListener("load", function () {
        try {
          state = core.validateState(JSON.parse(String(reader.result)));
          persist();
          render();
          showToast("Strict offline state imported.", "info");
        } catch (error) {
          showToast(error.message, "error");
        }
      });
      reader.addEventListener("error", function () {
        showToast("State file could not be read.", "error");
      });
      reader.readAsText(file, "utf-8");
    });

    render();
    return {
      getState: function () { return core.validateState(state); },
      dispatch,
    };
  }

  return { createCore, boot };
});
