import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  CircularProgress,
  useTheme,
  Chip
} from '@mui/material';
import { io } from "socket.io-client";
import { tokens } from '../../theme'; // Adjust import path as needed

const AnomalyTable = () => {
  const theme = useTheme();
  const colors = tokens(theme.palette.mode);

  const [anomalyData, setAnomalyData] = useState([]);
  const [anomalyCount, setAnomalyCount] = useState(0);
  const [totalCount, setTotalCount] = useState(0);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Connect to the Socket.IO server
    const socket = io("http://0.0.0.0:8000"); // Replace with your backend URL

    socket.on("connect", () => {
      setIsConnected(true);
    });

    socket.on("disconnect", () => {
      setIsConnected(false);
    });

    // Listen for 'anomaly_updates' event
    socket.on("anomaly_updates", (data) => {
      console.log("Received anomaly data:", data);
      setAnomalyData(data.data); // Update anomaly data
      setAnomalyCount(data.anomaly_count); // Update anomaly count
      setTotalCount(data.total_count); // Update total count
    });

    // Cleanup on component unmount
    return () => {
      socket.disconnect();
    };
  }, []);

  // Define table columns
  const columns = [
    { id: 'timestamp', label: 'Timestamp' },
    { id: 'duration', label: 'Duration' },
    { id: 'protocol_type', label: 'Protocol' },
    { id: 'service', label: 'Service' },
    { id: 'flag', label: 'Flag' },
    { id: 'src_bytes', label: 'Source Bytes' },
    { id: 'dst_bytes', label: 'Destination Bytes' },
    { id: 'anomaly_score', label: 'Anomaly Score' },
    { id: 'is_anomaly', label: 'Is Anomaly' }
  ];
  useEffect(() => {
    const socket = io("http://localhost:8000");

    socket.on("connect", () => {
      console.log("Connected to Socket.IO server");
      setIsConnected(true);
    });

    socket.on("disconnect", () => {
      console.log("Disconnected from Socket.IO server");
      setIsConnected(false);
    });

    socket.on("anomaly_updates", (data) => {
      console.log("Received anomaly data:", data);
      setAnomalyData(data.data);
      setAnomalyCount(data.anomaly_count);
      setTotalCount(data.total_count);
    });

    return () => {
      socket.disconnect();
    };
  }, []);
  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
        <Typography variant="h5" fontWeight="600">Network Traffic Analysis</Typography>
        <Box display="flex" gap={2}>
          <Chip
            label={`Anomalies: ${anomalyCount}`}
            color="error"
            variant="outlined"
            sx={{ fontWeight: 'bold' }}
          />
          <Chip
            label={`Total Records: ${totalCount}`}
            color="primary"
            variant="outlined"
          />
          <Chip
            label={isConnected ? "Connected" : "Disconnected"}
            color={isConnected ? "success" : "error"}
            variant="outlined"
          />
        </Box>
      </Box>

      {anomalyData.length > 0 ? (
        <TableContainer component={Paper} sx={{ backgroundColor: colors.primary[400], maxHeight: 600 }}>
          <Table stickyHeader aria-label="anomaly detection table">
            <TableHead>
              <TableRow>
                {columns.map((column) => (
                  <TableCell
                    key={column.id}
                    sx={{
                      backgroundColor: colors.blueAccent[700],
                      color: colors.grey[100],
                      fontWeight: 'bold'
                    }}
                  >
                    {column.label}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {anomalyData.map((row, index) => {
                const isAnomalous = row.is_anomaly;
                return (
                  <TableRow
                    key={index}
                    sx={{
                      backgroundColor: isAnomalous ? `${colors.redAccent[900]}80` : 'inherit',
                      '&:nth-of-type(odd)': {
                        backgroundColor: isAnomalous ? `${colors.redAccent[900]}80` : colors.primary[500]
                      },
                      '&:hover': { backgroundColor: colors.primary[300] }
                    }}
                  >
                    <TableCell>{row.timestamp}</TableCell>
                    <TableCell>{row.duration}</TableCell>
                    <TableCell>{row.protocol_type}</TableCell>
                    <TableCell>{row.service}</TableCell>
                    <TableCell>{row.flag}</TableCell>
                    <TableCell>{row.src_bytes}</TableCell>
                    <TableCell>{row.dst_bytes}</TableCell>
                    <TableCell>{typeof row.anomaly_score === 'number' ? row.anomaly_score.toFixed(2) : row.anomaly_score}</TableCell>
                    <TableCell>
                      <Chip
                        label={isAnomalous ? "YES" : "NO"}
                        color={isAnomalous ? "error" : "success"}
                        size="small"
                      />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      ) : (
        <Box display="flex" justifyContent="center" alignItems="center" p={4} sx={{ backgroundColor: colors.primary[400], height: 300 }}>
          {isConnected ? (
            <Box textAlign="center">
              <CircularProgress size={40} sx={{ mb: 2 }} />
              <Typography variant="body1">Waiting for network traffic data...</Typography>
            </Box>
          ) : (
            <Typography variant="body1" color="error">
              Disconnected from server. Check your FastAPI backend connection.
            </Typography>
          )}
        </Box>
      )}
    </Box>
  );
};

export default AnomalyTable;