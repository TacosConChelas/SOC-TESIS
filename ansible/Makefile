# Etapa 0 del pipeline (ADR-006 E1 / ansible/PIPELINE.md).
# Uso: entrar al shell (nix-shell) y ejecutar `make preflight`.
SHELL := $(shell command -v bash)
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

ANSIBLE_DIR := $(CURDIR)
REPO := $(abspath $(ANSIBLE_DIR)/..)
LOCAL := $(ANSIBLE_DIR)/local
LOGS := $(LOCAL)/.artifacts
TF_DIR := $(REPO)/terraform/lab
COMPOSE := docker compose -f $(LOCAL)/docker-compose.yml
PY := python3

export ANSIBLE_CONFIG := $(LOCAL)/ansible.cfg
export ANSIBLE_INVENTORY := $(LOCAL)/inventory.yml
export ANSIBLE_PRIVATE_KEY_FILE := $(LOCAL)/.keys/local_ed25519
export ANSIBLE_USER_KNOWN_HOSTS_FILE := $(LOCAL)/.known_hosts
# ssh usa por defecto ~/.ssh/known_hosts; se fuerza el desechable para no
# mezclar las claves de los contenedores con las del operador.
# IdentitiesOnly: MaxAuthTries es 3 y el agente del controlador puede tener
# varias llaves; sin esto ssh las ofrece primero y agota los intentos antes de
# la de ANSIBLE_PRIVATE_KEY_FILE ("Too many authentication failures").
export ANSIBLE_SSH_ARGS := -C -o ControlMaster=auto -o ControlPersist=60s -o IdentitiesOnly=yes -o UserKnownHostsFile=$(LOCAL)/.known_hosts -o GlobalKnownHostsFile=/dev/null

.PHONY: help lint tf-fmt tf-validate ansible-lint syntax-check tags-contract \
        secret-scan secret-scan-selftest keys up known-hosts ping down \
        toggle-install toggle-operate netcheck rehearse preflight \
        azure-session time-guard plan plan-check plan-check-selftest \
        gate-apply stage1 recap-check-selftest relay-check common-check clean

help:
	@echo "Etapa 0 - pre-vuelo local (sin Azure)"
	@echo "  make lint               terraform fmt/validate + ansible-lint + syntax-check"
	@echo "  make tags-contract      contrato de tags E1-8"
	@echo "  make secret-scan        escaneo de secretos (arbol de git)"
	@echo "  make secret-scan-selftest  planta secretos falsos y exige que falle"
	@echo "  make up                 construye y arranca los 4 contenedores (egreso abierto)"
	@echo "  make known-hosts        simula la Etapa 4a (known_hosts desechable)"
	@echo "  make ping               ansible all -m ping (4 pong)"
	@echo "  make toggle-install     abre egreso   (Etapa 3 simulada)"
	@echo "  make toggle-operate     cierra egreso (Etapa 7 simulada)"
	@echo "  make rehearse           1a pasada con cambios, 2a changed=0, --check, netcheck"
	@echo "  make recap-check-selftest  prueba los modos de recap-check.sh"
	@echo "  make relay-check        verifica el rol logrelay (requiere make rehearse previo)"
	@echo "  make common-check       verifica el rol common (requiere make rehearse previo)"
	@echo "  make preflight          lint + tags + secretos + ensayo  <-- Etapa 0"
	@echo "  make azure-session      az account show == EXPECTED_AZ_SUBSCRIPTION_NAME"
	@echo "  make time-guard         rechaza arrancar despues de 20:30 (E1-9)"
	@echo ""
	@echo "Etapa 1 - plan (sin apply)"
	@echo "  make plan               terraform plan -out=/tmp/tfplan + plan-check"
	@echo "  make plan-check         valida un JSON de plan (por defecto /tmp/tfplan.json)"
	@echo "  make plan-check-selftest  control + casos roto a-f"
	@echo "  make gate-apply         pide la frase de autorizacion (NO aplica)"
	@echo "  make stage1             azure-session + time-guard + plan + gate-apply"
	@echo "  make down / clean       destruye contenedores / todo el entorno local"

lint: tf-fmt tf-validate ansible-lint syntax-check

# Se valida sobre una copia temporal para no escribir .terraform/ en terraform/lab.
tf-fmt:
	@terraform fmt -check -recursive "$(TF_DIR)"
	@echo "tf-fmt: ok"

tf-validate:
	@tmp="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp"' EXIT; \
	cp -a "$(TF_DIR)/." "$$tmp/"; \
	terraform -chdir="$$tmp" init -backend=false -input=false >/dev/null; \
	terraform -chdir="$$tmp" validate

ansible-lint:
	@cd "$(ANSIBLE_DIR)" && ansible-lint --nocolor site.yml

syntax-check:
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --syntax-check

tags-contract:
	@"$(PY)" "$(LOCAL)/scripts/tags-contract.py"
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --list-tasks --tags start >/dev/null
	@echo "tags-contract: ok (--list-tasks --tags start compila)"

secret-scan:
	@cd "$(REPO)" && "$(PY)" ansible/local/scripts/secret-scan.py

secret-scan-selftest:
	@bash "$(LOCAL)/scripts/secret-scan-selftest.sh"

keys:
	@bash "$(LOCAL)/scripts/gen-local-keys.sh"

# BuildKit genera un ID de imagen distinto en cada build (metadatos y
# attestations), asi que `compose up --build` recreaba los 4 contenedores y
# perdia la convergencia. BUILDX_NO_DEFAULT_ATTESTATIONS=1 no lo evita; la
# imagen se sigue construyendo, pero los contenedores existentes no se tocan.
# Para aplicar cambios de Dockerfile/entrypoint: `make clean` y luego `make up`.
up: keys
	@$(COMPOSE) up -d --build --no-recreate
	@bash "$(LOCAL)/scripts/wait-sshd.sh"

known-hosts: up
	@bash "$(LOCAL)/scripts/gen-known-hosts.sh"

ping: known-hosts
	@cd "$(ANSIBLE_DIR)" && ansible all -m ansible.builtin.ping

toggle-install:
	@bash "$(LOCAL)/scripts/net-toggle.sh" install

toggle-operate:
	@bash "$(LOCAL)/scripts/net-toggle.sh" operate

netcheck:
	@bash "$(LOCAL)/scripts/netcheck.sh"

recap-check-selftest:
	@bash "$(LOCAL)/scripts/recap-check-selftest.sh"

relay-check:
	@bash "$(LOCAL)/scripts/relay-check.sh"

common-check:
	@bash "$(LOCAL)/scripts/common-check.sh"

rehearse: known-hosts
	@mkdir -p "$(LOGS)"
	@echo "== Etapa 6 simulada: egress abierto =="
	@bash "$(LOCAL)/scripts/net-toggle.sh" install
	@cd "$(ANSIBLE_DIR)" && ansible all -m ansible.builtin.ping 2>&1 | tee "$(LOGS)/ping.log"
	@test "$$(grep -c '"ping": "pong"' "$(LOGS)/ping.log")" -ge 4
	@echo "== 1a pasada: debe aplicar cambios =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags install,config 2>&1 | tee "$(LOGS)/pass1.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/pass1.log" changed
	@if docker exec soc-local-logrelay systemctl is-active --quiet nginx; then echo "FALLA: nginx arranco durante install,config (policy-rc.d no lo evito)" >&2; exit 1; fi
	@echo "== 2a pasada: debe ser idempotente =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags install,config 2>&1 | tee "$(LOGS)/pass2.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/pass2.log" nochange
	@echo "== control de drift: --check --diff tras converger =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags install,config --check --diff 2>&1 | tee "$(LOGS)/check.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/check.log" nochange
	@echo "== Etapa 7 simulada: egreso cerrado =="
	@bash "$(LOCAL)/scripts/net-toggle.sh" operate
	@echo "== arranque, 1a pasada: arrancar servicios es un cambio legitimo =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags start 2>&1 | tee "$(LOGS)/start1.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/start1.log" ok
	@echo "== arranque, 2a pasada: idempotente =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags start 2>&1 | tee "$(LOGS)/start2.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/start2.log" nochange
	@bash "$(LOCAL)/scripts/netcheck.sh"
	@echo "rehearse: ok. Para reabrir el egreso: make toggle-install"

preflight: lint tags-contract secret-scan secret-scan-selftest recap-check-selftest rehearse relay-check common-check
	@echo "preflight: Etapa 0 OK"

# Nombre de la suscripcion esperada: variable de entorno, nunca en el repo.
azure-session:
	@test -n "$(EXPECTED_AZ_SUBSCRIPTION_NAME)" || \
		{ echo "azure-session: define EXPECTED_AZ_SUBSCRIPTION_NAME (nombre de la suscripcion esperada)" >&2; exit 1; }; \
	command -v az >/dev/null || { echo "azure-session: az no instalado" >&2; exit 1; }; \
	name="$$(az account show --query name -o tsv 2>/dev/null)" || \
		{ echo "azure-session: sin sesion vigente (az login)" >&2; exit 1; }; \
	state="$$(az account show --query state -o tsv 2>/dev/null)" || exit 1; \
	[ "$$state" = "Enabled" ] || { echo "azure-session: la suscripcion activa esta en estado $$state" >&2; exit 1; }; \
	[ "$$name" = "$(EXPECTED_AZ_SUBSCRIPTION_NAME)" ] || \
		{ echo "azure-session: la suscripcion activa no es la esperada" >&2; exit 1; }; \
	echo "azure-session: ok (suscripcion esperada, estado Enabled)"

# TIMEGUARD_NOW=HH:MM permite probarlo sin esperar a la hora real.
time-guard:
	@now="$${TIMEGUARD_NOW:-$$(date +%H:%M)}"; \
	case "$$now" in [0-2][0-9]:[0-5][0-9]) ;; \
		*) echo "time-guard: TIMEGUARD_NOW invalido (usa HH:MM)" >&2; exit 2;; esac; \
	h=$$((10#$${now%%:*})); m=$$((10#$${now##*:})); \
	{ [ $$h -le 23 ] && [ $$m -le 59 ]; } || { echo "time-guard: TIMEGUARD_NOW fuera de rango" >&2; exit 2; }; \
	if [ $$h -gt 20 ] || { [ $$h -eq 20 ] && [ $$m -ge 30 ]; }; then \
		echo "time-guard: son las $$now; no iniciar el ciclo despues de 20:30 (E1-9)" >&2; \
		exit 1; \
	fi; \
	echo "time-guard: ok ($$now)"

# Etapa 1: plan guardado + checks. El JSON temporal lo borra stage1-plan.sh.
plan:
	@TF_DIR="$(TF_DIR)" PY="$(PY)" bash "$(LOCAL)/scripts/stage1-plan.sh"

plan-check:
	@"$(PY)" "$(LOCAL)/scripts/plan-check.py" "$${PLAN_JSON:-/tmp/tfplan.json}"

plan-check-selftest:
	@PY="$(PY)" bash "$(LOCAL)/scripts/plan-check-selftest.sh"

gate-apply:
	@bash "$(LOCAL)/scripts/gate-apply.sh"

stage1: azure-session time-guard plan gate-apply
	@echo "Etapa 1 lista; apply NO ejecutado"

down:
	@$(COMPOSE) down -v --remove-orphans

clean: down
	@rm -rf "$(LOGS)" "$(LOCAL)/.known_hosts" "$(LOCAL)/.keys" "$(LOCAL)/.selftest-scan.txt"
	@echo "clean: entorno local eliminado"
