import React, { useState, useEffect, useCallback, useMemo } from 'react'
import { viewQuery } from '../lib/pismo'

// TypeScript interfaces matching the backend structures
interface Order {
  is_buy: boolean
  order_id: number // u128 as number (may be in scientific notation)
  amount: number   // u128 as number
  account: number[] // [u8; 32] as number array
}

interface Tick {
  buy_list: number[]  // Vec<u128> as number array (may be in scientific notation)
  sell_list: number[] // Vec<u128> as number array (may be in scientific notation)
}

interface Orderbook {
  buy_asset: number[]  // [u8; 32] as number array
  sell_asset: number[] // [u8; 32] as number array
  ticks: Record<string, Tick> // BorshIndexMap<u64, Tick>
  orders: Record<string, Order> // BorshIndexMap<u128, Order>
}

// Processed order data for display
interface ProcessedOrder {
  price: number
  size: number
  total: number
  is_buy: boolean
  count: number // number of orders at this price level
}

interface OrderbookVisualizerProps {
  initialOrderbookAddress?: string
}

export default function OrderbookVisualizer({ initialOrderbookAddress = '' }: OrderbookVisualizerProps) {
  const [orderbookAddress, setOrderbookAddress] = useState<string>(initialOrderbookAddress)
  const [orderbook, setOrderbook] = useState<Orderbook | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string>('')
  const [autoRefresh, setAutoRefresh] = useState<boolean>(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  // Query orderbook data
  const fetchOrderbook = useCallback(async () => {
    if (!orderbookAddress.trim()) return

    try {
      setLoading(true)
      setError('')
      
      const result = await viewQuery(orderbookAddress.trim(), 'Orderbook')
      
      if (result === null) {
        setError('Orderbook not found')
        setOrderbook(null)
      } else {
        setOrderbook(result as Orderbook)
        setLastUpdated(new Date())
        setError('') // Clear any previous errors
      }
    } catch (e: any) {
      setError(`Query failed: ${e?.message || e}`)
      setOrderbook(null)
    } finally {
      setLoading(false)
    }
  }, [orderbookAddress])

  // Auto-refresh effect
  useEffect(() => {
    if (!autoRefresh) return

    const interval = setInterval(() => {
      fetchOrderbook()
    }, 1000) // 1 second interval

    return () => clearInterval(interval)
  }, [autoRefresh, fetchOrderbook])

  // Process orderbook data for display
  const processedData = useMemo(() => {
    if (!orderbook) return { buyOrders: [], sellOrders: [], spread: 0 }

    const buyOrders: ProcessedOrder[] = []
    const sellOrders: ProcessedOrder[] = []

    // Process each tick
    Object.entries(orderbook.ticks).forEach(([tickStr, tick]) => {
      const price = parseInt(tickStr)
      
      // Process buy orders at this tick
      if (tick.buy_list.length > 0) {
        let totalSize = 0
        tick.buy_list.forEach(orderId => {
          // Try multiple ways to find the order
          let order = null
          
          // Method 1: Direct string conversion
          const orderIdStr = orderId.toString()
          order = orderbook.orders[orderIdStr]
          
          // Method 2: If not found, try to find by matching the numeric value
          if (!order) {
            for (const [key, orderObj] of Object.entries(orderbook.orders)) {
              if (Number(orderObj.order_id) === Number(orderId)) {
                order = orderObj
                break
              }
            }
          }
          
          if (order && order.is_buy) {
            totalSize += Number(order.amount)
          }
        })
        
        if (totalSize > 0) {
          buyOrders.push({
            price,
            size: totalSize,
            total: 0, // Will be calculated below
            is_buy: true,
            count: tick.buy_list.length
          })
        }
      }

      // Process sell orders at this tick
      if (tick.sell_list.length > 0) {
        let totalSize = 0
        tick.sell_list.forEach(orderId => {
          // Try multiple ways to find the order
          let order = null
          
          // Method 1: Direct string conversion
          const orderIdStr = orderId.toString()
          order = orderbook.orders[orderIdStr]
          
          // Method 2: If not found, try to find by matching the numeric value
          if (!order) {
            for (const [key, orderObj] of Object.entries(orderbook.orders)) {
              if (Number(orderObj.order_id) === Number(orderId)) {
                order = orderObj
                break
              }
            }
          }
          
          if (order && !order.is_buy) {
            totalSize += Number(order.amount)
          }
        })
        
        if (totalSize > 0) {
          sellOrders.push({
            price,
            size: totalSize,
            total: 0, // Will be calculated below
            is_buy: false,
            count: tick.sell_list.length
          })
        }
      }
    })

    // Sort orders: buy orders descending by price, sell orders ascending by price
    buyOrders.sort((a, b) => b.price - a.price)
    sellOrders.sort((a, b) => a.price - b.price)

    // Calculate running totals
    let buyTotal = 0
    buyOrders.forEach(order => {
      buyTotal += order.size
      order.total = buyTotal
    })

    let sellTotal = 0
    sellOrders.forEach(order => {
      sellTotal += order.size
      order.total = sellTotal
    })

    // Calculate spread
    const bestBuy = buyOrders.length > 0 ? buyOrders[0].price : 0
    const bestSell = sellOrders.length > 0 ? sellOrders[0].price : 0
    const spread = bestSell > 0 && bestBuy > 0 ? bestSell - bestBuy : 0


    return { buyOrders, sellOrders, spread }
  }, [orderbook])

  const formatNumber = (num: number, decimals: number = 4): string => {
    return num.toLocaleString('en-US', { 
      minimumFractionDigits: decimals, 
      maximumFractionDigits: decimals 
    })
  }

  return (
    <div style={{ fontFamily: 'Inter, system-ui, sans-serif', maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ marginBottom: 24 }}>
        <h2>Orderbook Visualizer</h2>
        
        {/* Controls */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 16 }}>
          <input
            type="text"
            placeholder="Enter orderbook address (64-character hex)"
            value={orderbookAddress}
            onChange={(e) => setOrderbookAddress(e.target.value)}
            style={{ 
              flex: 1, 
              padding: '8px 12px', 
              border: '1px solid #ccc', 
              borderRadius: 4,
              fontSize: '12px',
              fontFamily: 'monospace'
            }}
          />
          <button 
            onClick={fetchOrderbook}
            disabled={loading || !orderbookAddress.trim()}
            style={{
              padding: '8px 16px',
              backgroundColor: loading || !orderbookAddress.trim() ? '#f0f0f0' : '#0066cc',
              color: loading || !orderbookAddress.trim() ? '#666' : 'white',
              border: 'none',
              borderRadius: 4,
              cursor: loading || !orderbookAddress.trim() ? 'not-allowed' : 'pointer'
            }}
          >
            {loading ? 'Loading...' : 'Query'}
          </button>
        </div>

        {/* Auto-refresh toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh every 1 second
          </label>
          {lastUpdated && (
            <span style={{ fontSize: '12px', color: '#666', marginLeft: 16 }}>
              Last updated: {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>

        {/* Error display */}
        {error && (
          <div style={{ 
            padding: 12, 
            backgroundColor: '#fee', 
            color: '#c33', 
            borderRadius: 4, 
            marginBottom: 16,
            fontSize: '14px'
          }}>
            {error}
          </div>
        )}
      </div>

      {/* Orderbook Display */}
      {orderbook && (
        <div style={{ 
          backgroundColor: '#1a1a1a', 
          color: '#fff', 
          borderRadius: 8, 
          overflow: 'hidden',
          fontFamily: 'monospace'
        }}>
          {/* Column headers */}
          <div style={{ 
            display: 'grid', 
            gridTemplateColumns: '1fr 1fr 1fr', 
            padding: '8px 16px',
            backgroundColor: '#2a2a2a',
            fontSize: '12px',
            color: '#888'
          }}>
            <div>Price</div>
            <div>Size</div>
            <div>Total</div>
          </div>

          {/* Sell orders (asks) - red background */}
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {processedData.sellOrders.slice().reverse().map((order, index) => (
              <div
                key={`sell-${order.price}`}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr 1fr',
                  padding: '4px 16px',
                  backgroundColor: index % 2 === 0 ? '#2a1a1a' : '#331a1a',
                  fontSize: '13px',
                  color: '#ff6b6b'
                }}
              >
                <div>{order.price}</div>
                <div>{formatNumber(order.size, 4)}</div>
                <div>{formatNumber(order.total, 4)}</div>
              </div>
            ))}
          </div>

          {/* Spread */}
          {processedData.spread > 0 && (
            <div style={{
              padding: '8px 16px',
              backgroundColor: '#333',
              textAlign: 'center',
              fontSize: '12px',
              color: '#888',
              borderTop: '1px solid #444',
              borderBottom: '1px solid #444'
            }}>
              <div>Spread</div>
              <div>{processedData.spread}</div>
              <div>0.00%</div>
            </div>
          )}

          {/* Buy orders (bids) - green background */}
          <div style={{ maxHeight: '300px', overflowY: 'auto' }}>
            {processedData.buyOrders.map((order, index) => (
              <div
                key={`buy-${order.price}`}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr 1fr',
                  padding: '4px 16px',
                  backgroundColor: index % 2 === 0 ? '#1a2a1a' : '#1a331a',
                  fontSize: '13px',
                  color: '#51cf66'
                }}
              >
                <div>{order.price}</div>
                <div>{formatNumber(order.size, 4)}</div>
                <div>{formatNumber(order.total, 4)}</div>
              </div>
            ))}
          </div>

          {/* Summary - always show when we have orderbook data */}
          <div style={{
            padding: '12px 16px',
            backgroundColor: '#2a2a2a',
            borderTop: '1px solid #444',
            fontSize: '12px',
            color: '#888'
          }}>
            <div>Orders: {Object.keys(orderbook.orders).length} total</div>
            <div>Ticks: {Object.keys(orderbook.ticks).length} total</div>
            <div>Buy levels: {processedData.buyOrders.length}</div>
            <div>Sell levels: {processedData.sellOrders.length}</div>
          </div>

          {/* Empty state */}
          {processedData.buyOrders.length === 0 && processedData.sellOrders.length === 0 && (
            <div style={{
              padding: '40px 16px',
              textAlign: 'center',
              color: '#888',
              fontSize: '14px'
            }}>
              {Object.keys(orderbook.orders).length > 0 
                ? `Orderbook has ${Object.keys(orderbook.orders).length} orders but none are displaying properly`
                : 'No orders in this orderbook'
              }
            </div>
          )}
        </div>
      )}
    </div>
  )
}
