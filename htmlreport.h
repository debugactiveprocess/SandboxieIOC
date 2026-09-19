/*
 * SandboxieIOC - self-contained HTML dashboard renderer.
 *
 * Renders the network/web IOC report as a single standalone HTML file
 * (inline CSS + JS, no server, no external dependencies) that can be opened
 * directly in a browser or served by any static file server.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License (v3) as published by the
 * Free Software Foundation.
 */

#pragma once

#include <QJsonObject>
#include <QString>

// Returns a complete <!DOCTYPE html> page embedding `report` as inline data.
QString renderNetworkReportHtml(const QJsonObject& report);
