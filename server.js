// ============================================================================
// ARCHIVO COMPLETO: server.js (Node.js + Express + PostgreSQL + JWT) - PARTE 8
// SECCIÓN: COMPORTAMIENTO INTERACTIVO CLIENTE, EXPORTACIÓN Y ESCUCHA ACTIVADA
// ============================================================================

                sessionStorage.setItem('mseptem_token', data.token);
                showToast('Firma validada. Concediendo acceso...', 'success');
                document.getElementById('twoFactorForm').reset();
                twoFactorView.classList.add('hidden');
                cargarMensajesDashboard();
                iniciarTemporizadorSesion(); 
            } else { 
                showToast('Error: ' + data.error, 'error'); 
            }
        } catch (error) { 
            showToast('Fallo crítico en factor de doble verificación.', 'error'); 
        }
    });

    // Procesamiento seguro del cambio de firma criptográfica
    document.getElementById('updatePasswordForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = sessionStorage.getItem('mseptem_token');
        const payload = { 
            passwordActual: document.getElementById('passwordActual').value, 
            passwordNuevo: document.getElementById('passwordNuevo').value 
        };
        try {
            const response = await fetch('/api/admin/update-password', { 
                method: 'POST', 
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }, 
                body: JSON.stringify(payload) 
            });
            const data = await response.json();
            if (response.ok) { 
                showToast('Firma actualizada. Autentíquese nuevamente.', 'success'); 
                ejecutarCierreSesionForzado(); 
            } else { 
                showToast('Error: ' + data.error, 'error'); 
            }
        } catch (error) { 
            showToast('Error al reestructurar firma criptográfica.', 'error'); 
        }
    });

    // Sincronización de la bitácora multicriterio en tiempo real
    async function cargarMensajesDashboard() {
        const token = sessionStorage.getItem('mseptem_token');
        try {
            const response = await fetch(\`/api/admin/mensajes?search=\${busquedaActual}&page=\${paginaActual}&limit=5\`, { 
                method: 'GET', 
                headers: { 'Authorization': 'Bearer ' + token } 
            });
            if(response.ok) {
                const resJson = await response.json();
                const mensajes = resJson.data;
                const pag = resJson.pagination;
                const tbody = document.getElementById('mensajesTableBody');
                tbody.innerHTML = '';
                
                if(mensajes.length === 0) { 
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No hay comunicaciones entrantes en el registro corporativo.</td></tr>'; 
                } else {
                    mensajes.forEach(m => {
                        const tr = document.createElement('tr');
                        const rangosMonto = { tier_1: '\$250K - \$1M', tier_2: '\$1M - \$5M', tier_3: '\$5M+' };
                        const inversionFormateada = rangosMonto[m.monto_inversion] || m.monto_inversion;
                        // Corrección estructural: Inyección explícita de celdas y filas HTML válidas
                        tr.innerHTML = '<td>' + m.nombre + '</td><td>' + m.email + '</td><td>' + m.telefono + '</td><td style="color:var(--gold-primary); font-weight:600;">' + inversionFormateada + '</td><td>' + m.pais + '</td><td>' + m.mensaje + '</td><td>' + new Date(m.fecha).toLocaleString() + '</td>';
                        tbody.appendChild(tr);
                    });
                }
                
                document.getElementById('pageIndicator').innerText = \`Página \${pag.page} de \${pag.totalPaginas || 1}\`;
                document.getElementById('prevPageBtn').disabled = pag.page <= 1;
                document.getElementById('nextPageBtn').disabled = pag.page >= pag.totalPaginas;
                
                publicView.classList.add('hidden'); 
                loginView.classList.add('hidden'); 
                configView.classList.add('hidden'); 
                twoFactorView.classList.add('hidden');
                dashboardView.classList.remove('hidden');
                
                renderizarGraficoMetricas();
            } else { 
                ejecutarCierreSesionForzado(); 
                showToast('Sesión inválida o expirada.', 'error'); 
            }
        } catch (error) { 
            showToast('Fallo al sincronizar consola corporativa.', 'error'); 
        }
    }

    // Exportador de auditorías físicas a formato CSV (Alineado multicolumna)
    document.getElementById('exportCsvBtn').addEventListener('click', async () => {
        const token = sessionStorage.getItem('mseptem_token');
        try {
            const response = await fetch(\`/api/admin/mensajes?search=\${busquedaActual}&page=1&limit=1000\`, { 
                method: 'GET', 
                headers: { 'Authorization': 'Bearer ' + token } 
            });
            if(response.ok) {
                const resJson = await response.json();
                const mensajes = resJson.data;
                if(mensajes.length === 0) { 
                    showToast('No existen registros para exportar.', 'error'); 
                    return; 
                }
                
                let csvContent = "\\uFEFF"; // BOM para compatibilidad con caracteres utf-8 en Excel
                csvContent += "ID,Remitente,Contacto,Telefono,Rango Inversion,Pais,Requerimiento,Fecha\\n";
                mensajes.forEach(m => { 
                    csvContent += \`\${m.id},"\${m.nombre}","\${m.email}","\${m.telefono}","\${m.monto_inversion}","\${m.pais}","\${m.mensaje}","\${new Date(m.fecha).toLocaleString()}"\\n\`; 
                });
                
                const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.setAttribute("href", url); 
                link.setAttribute("download", \`MSEPTEM_AUDIT_\${new Date().toISOString().slice(0,10)}.csv\`);
                document.body.appendChild(link); 
                link.click(); 
                document.body.removeChild(link);
            }
        } catch (error) { 
            showToast('Error de empaquetado al exportar la bitácora.', 'error'); 
        }
    });

    // Protocolo preventivo por inactividad de operadores
    function ejecutarCierreSesionForzado() {
        clearInterval(cuentaRegresivaInactividad);
        sessionStorage.removeItem('mseptem_token');
        dashboardView.classList.add('hidden'); 
        configView.classList.add('hidden'); 
        publicView.classList.remove('hidden');
        showToast('Consola de administración cerrada de forma segura.', 'success');
    }

    document.getElementById('logoutBtn').addEventListener('click', ejecutarCierreSesionForzado);
    </script>
</body>
</html>
    `);
});

// Inicialización del servidor web seguro y bindeo de puertos dinámicos para producción
app.listen(PORT, () => {
    console.log(`[SEGURIDAD] Servidor MSEPTEM activo y enlazado en puerto ${PORT}`);
});
